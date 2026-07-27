namespace Cirreum.Authentication.External;

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

	private static readonly HashSet<string> ExternalReservedClaimTypes =
		new(StringComparer.Ordinal) { ExternalClaimTypes.TenantSlug, ExternalClaimTypes.AuthScheme };

	// Whether a credential was actually presented, as opposed to the request simply not carrying one.
	// RFC 6750 §3.1 scopes error="invalid_token" to a supplied-but-rejected credential; a bare
	// challenge is the correct response to a request that presented nothing.
	private bool _credentialPresented;

	protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
		// Reset per-invocation state (the handler instance may be reused within a request).
		this._credentialPresented = false;

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

		// A credential for this scheme was presented — everything from here fails with
		// error="invalid_token" rather than a bare challenge.
		this._credentialPresented = true;

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

		// 4. Pre-read the token for routing hints and early rejection. Every value read here is
		// UNVERIFIED — the signature is not checked until step 10 — so these may be used to reject
		// and to select a stored configuration, never to establish trust.
		JsonWebToken? parsedToken = null;
		string? tokenIssuer = null;
		IReadOnlyList<string> tokenAudiences = [];
		string? tokenType = null;
		string? tokenClientId = null;

		// CanReadToken is a shallow structural check; ReadJsonWebToken still parses JSON and can
		// throw on input that passes it. This runs before the validation try/catch below, so an
		// unguarded throw here escapes as a 500 instead of failing authentication. A token that
		// cannot be read leaves every hint null, and each check below fails closed on that.
		try {
			if (this._tokenHandler.CanReadToken(token)) {
				parsedToken = this._tokenHandler.ReadJsonWebToken(token);
			}
		} catch (Exception ex) {
			if (this.Logger.IsEnabled(LogLevel.Debug)) {
				this.Logger.LogDebug(ex, "Presented token could not be parsed for tenant {TenantSlug}", tenantSlug);
			}
			parsedToken = null;
		}

		if (parsedToken is not null) {
			tokenIssuer = parsedToken.Issuer;
			tokenAudiences = ReadClaimValues(parsedToken, ExternalDefaults.DefaultAudienceClaim);
			tokenType = parsedToken.Typ;
			// Try azp first (OAuth 2.0), then client_id (some IdPs use this)
			tokenClientId = parsedToken.TryGetPayloadValue<string>("azp", out var azp) ? azp : null;
			tokenClientId ??= parsedToken.TryGetPayloadValue<string>("client_id", out var cid) ? cid : null;
		}

		// Nothing in OpenID Connect marks a token as an ID token — there is no standard `typ` value
		// for one — so the handler does not try to read the answer off the token. What separates an
		// access token from an ID token is the audience, PROVIDED the tenant's API audience is
		// distinct from the client ID that requested sign-in. That is the usual arrangement but not a
		// guarantee: an IdP that issues access tokens audienced to the client itself (Entra v1 can)
		// produces both kinds carrying the same `aud`, and audience validation cannot tell them
		// apart. Where a provider exposes a discriminator — RFC 9068 `typ: at+jwt`, or a claim of its
		// own — RequiredClaims and RequireAccessTokenType are how a tenant declares it.

		// 5. Resolve tenant configuration
		var resolutionContext = new ExternalResolutionContext {
			TenantSlug = tenantSlug,
			TokenIssuer = tokenIssuer,
			TokenAudiences = tokenAudiences,
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
				if (!claimType.HasValue()) {
					this.Logger.LogError(
						"Tenant {TenantSlug} has a RequiredClaims entry with a blank claim type. A requirement " +
						"naming no claim cannot be checked, so it is treated as a misconfiguration rather than " +
						"silently skipped.",
						tenantSlug);
					return this.FailWithMessage("Tenant configuration is invalid");
				}

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
			var presented = parsedToken is not null
				? ReadClaimValues(parsedToken, tenantConfig.AudienceClaim)
				: [];

			if (!presented.Any(value => value.HasValue() && validAudiences.Contains(value, StringComparer.Ordinal))) {
				this.Logger.LogWarning(
					"Audience validation failed for tenant {TenantSlug}: claim '{AudienceClaim}' was '{Actual}'",
					tenantSlug,
					tenantConfig.AudienceClaim,
					presented.Length == 0 ? "(absent)" : string.Join(", ", presented));
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

			// Ordinal: a client ID is an opaque identifier, and no major IdP documents it as
			// case-insensitive. Folding case can only widen the set of accepted callers.
			if (!tenantConfig.AllowedClientIds.Contains(tokenClientId, StringComparer.Ordinal)) {
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
			// Null accepts whatever the tenant's published keys support; a tenant that pins its
			// algorithms stops a token being accepted under one they never meant to use.
			ValidAlgorithms = tenantConfig.ValidAlgorithms,
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
		var principal = this.BuildClaimsPrincipal(validationResult.ClaimsIdentity, tenantConfig, this.Scheme.Name);

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

	// A JWT claim may hold a single value or an array — `aud` most visibly (RFC 7519 §4.1.3), but any
	// claim a tenant nominates can be either. TryGetPayloadValue<string> returns false for an array,
	// which would read a valid multi-audience token as carrying no audience at all.
	private static string[] ReadClaimValues(JsonWebToken token, string claimType) {
		// Array first: reading an array-valued claim as a string does not fail cleanly — it yields a
		// single coerced value — so a string-first order would silently see only part of the claim
		// and never reach this branch. Reading a scalar as an array does fail cleanly, so the
		// fallback below is the safe direction.
		if (token.TryGetPayloadValue<string[]>(claimType, out var many)) {
			return many is null ? [] : many;
		}

		if (token.TryGetPayloadValue<string>(claimType, out var single)) {
			return single is null ? [] : [single];
		}

		return [];
	}

	private ClaimsPrincipal BuildClaimsPrincipal(
		ClaimsIdentity identity,
		ExternalTenantConfig tenantConfig,
		string schemeName) {

		// The identity is rebuilt rather than appended to, because the claims the handler stamps are
		// reserved. A tenant's token carrying `tenant_slug`, or a ClaimMappings entry targeting it,
		// would otherwise leave two claims of that type on the identity — and FindFirst returns the
		// token's, because it was added first. On a multi-tenant boundary that is a tenant-spoofing
		// primitive, not a cosmetic duplicate.
		var claims = new List<Claim>(identity.Claims.Count() + 2);
		var hasMappings = tenantConfig.ClaimMappings is { Count: > 0 };

		foreach (var claim in identity.Claims) {
			var claimType = hasMappings
				&& tenantConfig.ClaimMappings!.TryGetValue(claim.Type, out var mappedType)
					? mappedType
					: claim.Type;

			if (ExternalReservedClaimTypes.Contains(claimType)) {
				this.Logger.LogWarning(
					"Discarded a reserved claim '{ClaimType}' arriving from tenant {TenantSlug}'s token. " +
					"The framework stamps this claim itself; a token or claim mapping supplying it cannot " +
					"be allowed to shadow the resolved value.",
					claimType, tenantConfig.Slug);
				continue;
			}

			claims.Add(string.Equals(claimType, claim.Type, StringComparison.Ordinal)
				? claim
				: new Claim(claimType, claim.Value, claim.ValueType, claim.Issuer));
		}

		claims.Add(new Claim(ExternalClaimTypes.TenantSlug, tenantConfig.Slug));
		claims.Add(new Claim(ExternalClaimTypes.AuthScheme, schemeName));

		return new ClaimsPrincipal(new ClaimsIdentity(
			claims, identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType));

	}

	protected override Task HandleChallengeAsync(AuthenticationProperties properties) {
		this.Response.StatusCode = 401;

		// A request that presented no credential gets a bare challenge — error="invalid_token" would
		// assert a token was supplied and rejected, which tells a client to stop retrying with a
		// credential it never sent.
		if (!this._credentialPresented) {
			this.Response.Headers.WWWAuthenticate = $"Bearer realm=\"{this.Scheme.Name}\"";
			return Task.CompletedTask;
		}

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
