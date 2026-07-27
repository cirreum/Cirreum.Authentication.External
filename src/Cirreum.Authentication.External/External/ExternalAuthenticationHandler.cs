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
		JsonWebToken? parsedToken = null;
		string? tokenIssuer = null;
		string? tokenAudience = null;
		string? tokenType = null;
		string? tokenClientId = null;

		if (this._tokenHandler.CanReadToken(token)) {
			parsedToken = this._tokenHandler.ReadJsonWebToken(token);
			tokenIssuer = parsedToken.Issuer;
			// TryGetPayloadValue, not GetPayloadValue: the latter throws when the claim is absent,
			// which turns a token carrying no `aud` — legal, and what AWS Cognito issues — into an
			// unhandled exception and a 500 rather than a failed authentication.
			tokenAudience = parsedToken.TryGetPayloadValue<string>(
				ExternalDefaults.DefaultAudienceClaim, out var audienceValue) ? audienceValue : null;
			tokenType = parsedToken.Typ;
			// Try azp first (OAuth 2.0), then client_id (some IdPs use this)
			tokenClientId = parsedToken.TryGetPayloadValue<string>("azp", out var azp) ? azp : null;
			tokenClientId ??= parsedToken.TryGetPayloadValue<string>("client_id", out var cid) ? cid : null;
		}

		// An ID token presented as an access token is rejected by audience validation below, not by
		// inspecting what the token says about itself. Nothing in OpenID Connect marks an ID token
		// as one — there is no standard `typ` value for it — so any header or claim check would be
		// vendor-specific and silent where the vendor does not participate. Audience validation
		// holds everywhere instead: a tenant's ValidAudiences name this API, an ID token's `aud`
		// names the client that requested sign-in, and validation is mandatory and fails closed.
		// A tenant whose IdP does not fit that model moves the check via AudienceClaim, and then
		// owes a discriminator through RequiredClaims — see step 7c.

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

		// 7a. Require the RFC 9068 access-token type, for tenants whose IdP emits it. Opt-in per
		// tenant because `at+jwt` is opt-in in practice — Entra, Cognito and Auth0 all emit plain
		// `JWT` for access tokens by default — so requiring it globally would reject valid tokens
		// from most IdPs. A missing `typ` fails this check, which is the intent when a tenant has
		// asserted their IdP stamps it.
		if (tenantConfig.RequireAccessTokenType) {
			if (!string.Equals(tokenType, "at+jwt", StringComparison.OrdinalIgnoreCase)) {
				this.Logger.LogWarning(
					"Token type validation failed for tenant {TenantSlug}: expected 'at+jwt', got '{TokenType}'",
					tenantSlug, tokenType ?? "(none)");
				return this.FailWithMessage("Token must be an access token (at+jwt)");
			}
		}

		// 7b. Claims this tenant's IdP is known to stamp. Rejecting here, before the signature is
		// verified, is safe because step 10 still has to pass — a forged claim value cannot survive
		// both gates — and it keeps the cheap check ahead of the expensive one.
		var usesStandardAudience = string.Equals(
			tenantConfig.AudienceClaim, ExternalDefaults.DefaultAudienceClaim, StringComparison.Ordinal);

		// Blank entries are dropped rather than compared. A tenant record carrying an empty audience
		// string would otherwise match a token presenting an empty one — a blank value that becomes
		// an acceptance instead of a rejection. Once dropped, a config with nothing left has
		// configured no audience at all, which is refused rather than allowed to validate against an
		// empty set.
		var validAudiences = tenantConfig.ValidAudiences.Where(audience => audience.HasValue()).ToArray();

		if (validAudiences.Length == 0) {
			this.Logger.LogError(
				"Tenant {TenantSlug} has no non-blank entries in ValidAudiences. The audience is what " +
				"separates an access token issued for this API from an ID token issued for a client, " +
				"so there is no configuration under which this tenant can authenticate safely.",
				tenantSlug);
			return this.FailWithMessage("Tenant configuration is invalid");
		}

		// A tenant that moves the audience off `aud` has moved it off the check that separates an
		// access token from an ID token, so it must supply something that does. Refusing the
		// configuration outright is the point: the alternative is a tenant silently accepting ID
		// tokens as bearer credentials because one field was set without the other.
		if (!usesStandardAudience && tenantConfig.RequiredClaims is not { Count: > 0 }) {
			this.Logger.LogError(
				"Tenant {TenantSlug} sets AudienceClaim to '{AudienceClaim}' without any RequiredClaims. " +
				"Moving the audience off '{DefaultAudienceClaim}' removes the check that distinguishes an " +
				"access token from an ID token, so a claim that distinguishes them must be required instead.",
				tenantSlug, tenantConfig.AudienceClaim, ExternalDefaults.DefaultAudienceClaim);
			return this.FailWithMessage("Tenant configuration is invalid");
		}

		if (tenantConfig.RequiredClaims is { Count: > 0 }) {
			if (parsedToken is null) {
				this.Logger.LogWarning(
					"Required-claim validation failed for tenant {TenantSlug}: token could not be read",
					tenantSlug);
				return this.FailWithMessage("Token is not a readable JWT");
			}

			foreach (var (claimType, requiredValue) in tenantConfig.RequiredClaims) {
				var actual = parsedToken.TryGetPayloadValue<string>(claimType, out var value) ? value : null;
				if (!string.Equals(actual, requiredValue, StringComparison.Ordinal)) {
					this.Logger.LogWarning(
						"Required-claim validation failed for tenant {TenantSlug}: '{ClaimType}' was '{Actual}', expected '{Expected}'",
						tenantSlug, claimType, actual ?? "(absent)", requiredValue);
					return this.FailWithMessage($"Token claim '{claimType}' does not have the required value");
				}
			}
		}

		// 7c. Audience, when the tenant's IdP carries it somewhere other than `aud`.
		// TokenValidationParameters can only validate `aud`, so standard validation is switched off
		// below and the equivalent check happens here against the same ValidAudiences.
		if (!usesStandardAudience) {
			var actualAudience = parsedToken is not null
				&& parsedToken.TryGetPayloadValue<string>(tenantConfig.AudienceClaim, out var aud)
					? aud
					: null;

			if (!actualAudience.HasValue()
				|| !validAudiences.Contains(actualAudience, StringComparer.Ordinal)) {

				this.Logger.LogWarning(
					"Audience validation failed for tenant {TenantSlug}: claim '{AudienceClaim}' was '{Actual}'",
					tenantSlug, tenantConfig.AudienceClaim, actualAudience ?? "(absent)");
				return this.FailWithMessage("Token audience is not valid for this tenant");
			}
		}

		// 7d. Validate authorized party (azp/client_id) if configured
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
			// Off only when the tenant carries its audience in another claim, which step 7c has
			// already checked against these same audiences. It is never simply skipped.
			ValidateAudience = usesStandardAudience,
			ValidAudiences = validAudiences,
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
