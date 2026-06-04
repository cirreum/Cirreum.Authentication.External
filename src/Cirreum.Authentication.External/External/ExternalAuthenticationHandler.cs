namespace Cirreum.Authentication.External;

using Cirreum;
using Cirreum.Security;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler for BYOID (Bring Your Own Identity) authentication.
/// Validates JWT tokens against dynamically resolved tenant IdPs.
/// </summary>
public class ExternalAuthenticationHandler(
	IOptionsMonitor<ExternalAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	IExternalTenantResolver tenantResolver,
	IExternalConfigurationManager configurationManager,
	ITenantIdentifierExtractor tenantExtractor
) : AuthenticationHandler<ExternalAuthenticationOptions>(options, logger, encoder) {

	private readonly JsonWebTokenHandler _tokenHandler = new JsonWebTokenHandler();

	protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
		// 1. Extract tenant identifier
		var tenantSlug = tenantExtractor.Extract(this.Context);
		if (string.IsNullOrEmpty(tenantSlug)) {
			// No tenant identifier - this handler doesn't apply
			return AuthenticateResult.NoResult();
		}

		// 2. Extract bearer token
		var authHeader = this.Request.Headers.Authorization.ToString();
		if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
			return this.FailWithMessage("Missing or invalid Authorization header");
		}

		var token = authHeader["Bearer ".Length..].Trim();
		if (string.IsNullOrEmpty(token)) {
			return this.FailWithMessage("Empty bearer token");
		}

		// 3. Validate tenant in path if configured (defense in depth)
		if (this.Options.ValidateTenantInPath) {
			var pathTenant = tenantExtractor.ExtractFromPath(this.Context, this.Options.ValidationPathSegmentIndex);
			if (!string.Equals(tenantSlug, pathTenant, StringComparison.OrdinalIgnoreCase)) {
				this.Logger.LogWarning(
					"Tenant mismatch: primary source={PrimaryTenant}, path={PathTenant}",
					tenantSlug, pathTenant);
				return this.FailWithMessage("Tenant identifier mismatch");
			}
		}

		// 4. Pre-read token to get issuer/audience for resolution context and early validation
		string? tokenIssuer = null;
		string? tokenAudience = null;
		string? tokenType = null;
		string? tokenClientId = null;

		if (this._tokenHandler.CanReadToken(token)) {
			var parsedToken = this._tokenHandler.ReadJsonWebToken(token);
			tokenIssuer = parsedToken.Issuer;
			tokenAudience = parsedToken.GetPayloadValue<string>("aud");
			tokenType = parsedToken.Typ;
			// Try azp first (OAuth 2.0), then client_id (some IdPs use this)
			tokenClientId = parsedToken.TryGetPayloadValue<string>("azp", out var azp) ? azp : null;
			tokenClientId ??= parsedToken.TryGetPayloadValue<string>("client_id", out var cid) ? cid : null;
		}

		// 4a. Reject tokens with missing or invalid type
		// This check happens before tenant resolution to fail fast
		if (string.IsNullOrEmpty(tokenType)) {
			this.Logger.LogWarning("Rejected token with missing typ header");
			return this.FailWithMessage("Token must have a typ header");
		}

		if (tokenType.Equals("id_token", StringComparison.OrdinalIgnoreCase)) {
			this.Logger.LogWarning("Rejected ID token used as access token");
			return this.FailWithMessage("ID tokens cannot be used as access tokens");
		}

		// 5. Resolve tenant configuration
		var resolutionContext = new ExternalResolutionContext {
			TenantSlug = tenantSlug,
			TokenIssuer = tokenIssuer,
			TokenAudience = tokenAudience,
			RawToken = token
		};

		ExternalTenantConfig? tenantConfig;
		try {
			tenantConfig = await tenantResolver.ResolveAsync(resolutionContext, this.Context.RequestAborted);
		} catch (Exception ex) {
			this.Logger.LogError(ex, "Failed to resolve tenant configuration for {TenantSlug}", tenantSlug);
			return this.FailWithMessage("Failed to resolve tenant configuration");
		}

		// 6. Handle tenant not found
		if (tenantConfig is null) {
			this.Logger.LogWarning("Tenant not found: {TenantSlug}", tenantSlug);
			return this.HandleTenantNotFound(tenantSlug);
		}

		// 7. Handle disabled tenant
		if (!tenantConfig.IsEnabled) {
			this.Logger.LogWarning("Tenant disabled: {TenantSlug}", tenantSlug);
			return this.FailWithMessage("Tenant is disabled");
		}

		// 7a. Validate token type (access token required if configured)
		// Note: null/missing typ and id_token are already rejected before tenant resolution
		if (tenantConfig.RequireAccessTokenType) {
			if (!tokenType!.Equals("at+jwt", StringComparison.OrdinalIgnoreCase)) {
				this.Logger.LogWarning(
					"Token type validation failed for tenant {TenantSlug}: expected 'at+jwt', got '{TokenType}'",
					tenantSlug, tokenType);
				return this.FailWithMessage("Token must be an access token (at+jwt)");
			}
		}

		// 7b. Validate authorized party (azp/client_id) if configured
		if (tenantConfig.AllowedClientIds is { Count: > 0 }) {
			if (string.IsNullOrEmpty(tokenClientId)) {
				this.Logger.LogWarning(
					"Client ID validation failed for tenant {TenantSlug}: no azp or client_id claim in token",
					tenantSlug);
				return this.FailWithMessage("Token missing client identifier (azp/client_id)");
			}

			if (!tenantConfig.AllowedClientIds.Contains(tokenClientId, StringComparer.OrdinalIgnoreCase)) {
				this.Logger.LogWarning(
					"Client ID validation failed for tenant {TenantSlug}: '{ClientId}' not in allowed list",
					tenantSlug, tokenClientId);
				return this.FailWithMessage("Token client ID not allowed for this tenant");
			}
		}

		// 8. Get OIDC configuration for tenant's IdP
		OpenIdConnectConfiguration? oidcConfig;
		try {
			oidcConfig = await configurationManager.GetConfigurationAsync(
				tenantConfig.MetadataAddress,
				this.Options.RequireHttpsMetadata,
				this.Context.RequestAborted);
		} catch (Exception ex) {
			this.Logger.LogError(ex,
				"Failed to retrieve OIDC configuration for tenant {TenantSlug} from {MetadataAddress}",
				tenantSlug, tenantConfig.MetadataAddress);
			return this.FailWithMessage("Failed to retrieve IdP configuration");
		}

		// 9. Build token validation parameters
		var validationParameters = new TokenValidationParameters {
			ValidateIssuer = true,
			ValidIssuer = tenantConfig.ValidIssuerOverride ?? oidcConfig.Issuer,
			ValidateAudience = true,
			ValidAudiences = tenantConfig.ValidAudiences,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			IssuerSigningKeys = oidcConfig.SigningKeys,
			ClockSkew = this.Options.ClockSkew
		};

		// 10. Validate token
		TokenValidationResult validationResult;
		try {
			validationResult = await this._tokenHandler.ValidateTokenAsync(token, validationParameters);
		} catch (Exception ex) {
			this.Logger.LogWarning(ex, "Token validation failed for tenant {TenantSlug}", tenantSlug);
			return this.FailWithMessage("Token validation failed");
		}

		if (!validationResult.IsValid) {
			this.Logger.LogWarning(
				"Token validation failed for tenant {TenantSlug}: {Error}",
				tenantSlug, validationResult.Exception?.Message ?? "Unknown error");
			return this.FailWithMessage("Invalid token");
		}

		// 11. Build claims principal with normalized claims
		var principal = BuildClaimsPrincipal(validationResult.ClaimsIdentity, tenantConfig, this.Scheme.Name);

		// 12. Store tenant context for downstream use
		this.Context.Items["External:TenantSlug"] = tenantSlug;
		this.Context.Items["External:TenantConfig"] = tenantConfig;

		var ticket = new AuthenticationTicket(principal, this.Scheme.Name);
		return AuthenticateResult.Success(ticket);
	}

	private AuthenticateResult HandleTenantNotFound(string tenantSlug) {
		return this.Options.TenantNotFoundBehavior switch {
			TenantNotFoundBehavior.Fallback => AuthenticateResult.NoResult(),
			TenantNotFoundBehavior.RejectWithLogging => this.FailWithMessage($"Tenant not found: {tenantSlug}"),
			_ => this.FailWithMessage("Authentication failed")
		};
	}

	private AuthenticateResult FailWithMessage(string message) {
		var displayMessage = this.Options.DetailedErrors ? message : "Authentication failed";
		return AuthenticateResult.Fail(displayMessage);
	}

	private static ClaimsPrincipal BuildClaimsPrincipal(
		ClaimsIdentity identity,
		ExternalTenantConfig tenantConfig,
		string schemeName) {

		// Apply custom claim mappings if configured
		if (tenantConfig.ClaimMappings is { Count: > 0 }) {
			var mappedClaims = new List<Claim>();
			foreach (var claim in identity.Claims) {
				if (tenantConfig.ClaimMappings.TryGetValue(claim.Type, out var mappedType)) {
					mappedClaims.Add(new Claim(mappedType, claim.Value, claim.ValueType, claim.Issuer));
				} else {
					mappedClaims.Add(claim);
				}
			}
			identity = new ClaimsIdentity(mappedClaims, identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
		}

		// Add tenant context claims
		identity.AddClaim(new Claim("tenant_slug", tenantConfig.Slug));
		identity.AddClaim(new Claim("auth_scheme", schemeName));

		// Use ClaimsHelper for additional normalization
		var provider = ClaimsHelper.ResolveProvider(identity);
		if (provider != IdentityProviderType.Unknown) {
			identity.AddClaim(new Claim("idp_type", provider.ToString()));
		}

		return new ClaimsPrincipal(identity);

	}

	protected override Task HandleChallengeAsync(AuthenticationProperties properties) {
		this.Response.StatusCode = 401;

		// RFC 6750 Section 3.1: Include error code in WWW-Authenticate header
		// "invalid_token" is the appropriate error for JWT validation failures
		this.Response.Headers.WWWAuthenticate = $"Bearer realm=\"{this.Scheme.Name}\", error=\"invalid_token\"";
		return Task.CompletedTask;
	}

	protected override Task HandleForbiddenAsync(AuthenticationProperties properties) {
		this.Response.StatusCode = 403;
		return Task.CompletedTask;
	}
}
