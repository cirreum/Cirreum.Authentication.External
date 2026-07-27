namespace Cirreum.Authentication.External.Tests;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Encodings.Web;

/// <summary>
/// Request-path proofs for <see cref="ExternalAuthenticationHandler"/>, covering the per-tenant
/// checks that run before signature validation.
/// </summary>
/// <remarks>
/// The configuration manager stub throws if it is reached, and the handler reports that as
/// "Failed to retrieve IdP configuration". So a test asserting any other failure message is also
/// asserting the tenant's IdP was never contacted — these checks sit ahead of metadata retrieval
/// deliberately, so a request that cannot succeed costs a customer's identity provider nothing.
/// </remarks>
public sealed class ExternalAuthenticationHandlerTests {

	private const string Slug = "acme";
	private const string Issuer = "https://idp.example.com/";
	private const string ApiAudience = "https://api.example.com";

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T> {
		public T CurrentValue => value;
		public T Get(string? name) => value;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class StubResolver(ExternalTenantConfig? config) : IExternalTenantResolver {
		public Task<ExternalTenantConfig?> ResolveAsync(
			ExternalResolutionContext context,
			CancellationToken cancellationToken = default) => Task.FromResult(config);
	}

	/// <summary>Fails the test if the request ever reaches outbound metadata retrieval.</summary>
	private sealed class UnreachableConfigurationManager : IExternalConfigurationManager {

		public Task<OpenIdConnectConfiguration> GetConfigurationAsync(
			string metadataAddress,
			bool requireHttps,
			CancellationToken ct = default) =>
			throw new InvalidOperationException(
				"The tenant IdP was contacted for a request that should have been rejected first.");

		public Task RefreshConfigurationAsync(string metadataAddress, CancellationToken ct = default) =>
			throw new InvalidOperationException("Unexpected refresh.");
	}

	private static readonly SymmetricSecurityKey SigningKey =
		new(Encoding.UTF8.GetBytes(new string('k', 64)));

	/// <summary>Serves the signing key, so a token can validate end to end.</summary>
	private sealed class StubConfigurationManager : IExternalConfigurationManager {

		public Task<OpenIdConnectConfiguration> GetConfigurationAsync(
			string metadataAddress,
			bool requireHttps,
			CancellationToken ct = default) {

			var configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
			configuration.SigningKeys.Add(SigningKey);
			return Task.FromResult(configuration);
		}

		public Task RefreshConfigurationAsync(string metadataAddress, CancellationToken ct = default) =>
			Task.CompletedTask;
	}

	private static string CreateToken(Dictionary<string, object> claims, string? tokenType = null) {
		return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor {
			Issuer = Issuer,
			Claims = claims,
			TokenType = tokenType,
			SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256)
		});
	}

	private static ExternalTenantConfig TenantConfig(
		string audienceClaim = ExternalDefaults.DefaultAudienceClaim,
		IReadOnlyDictionary<string, string>? requiredClaims = null,
		IReadOnlyList<string>? validAudiences = null) =>
		new() {
			Slug = Slug,
			IsEnabled = true,
			MetadataAddress = $"{Issuer}.well-known/openid-configuration",
			ValidAudiences = validAudiences ?? [ApiAudience],
			AudienceClaim = audienceClaim,
			RequiredClaims = requiredClaims
		};

	private static async Task<AuthenticateResult> AuthenticateAsync(
		ExternalTenantConfig tenantConfig,
		string token,
		IExternalConfigurationManager? configurationManager = null) {

		var options = new ExternalAuthenticationOptions {
			TenantIdentifierSource = TenantIdentifierSource.Header,
			TenantHeaderName = ExternalDefaults.DefaultTenantHeaderName,
			DetailedErrors = true
		};

		var monitor = new StaticOptionsMonitor<ExternalAuthenticationOptions>(options);

		var handler = new ExternalAuthenticationHandler(
			monitor,
			NullLoggerFactory.Instance,
			UrlEncoder.Default,
			new StubResolver(tenantConfig),
			configurationManager ?? new UnreachableConfigurationManager(),
			new TenantIdentifierExtractor(options));

		var context = new DefaultHttpContext();
		context.Request.Headers[ExternalDefaults.DefaultTenantHeaderName] = Slug;
		context.Request.Headers.Authorization = $"Bearer {token}";

		await handler.InitializeAsync(
			new AuthenticationScheme(
				ExternalDefaults.AuthenticationScheme, null, typeof(ExternalAuthenticationHandler)),
			context);

		return await handler.AuthenticateAsync();
	}

	[Fact]
	public async Task A_tenant_moving_the_audience_without_a_required_claim_is_refused() {
		// The coupling that makes the seam safe. Moving the audience off `aud` removes the check
		// that separates an access token from an ID token, so a configuration that does the first
		// without the second must not authenticate anyone — silently accepting ID tokens as bearer
		// credentials is exactly the failure this guard exists to prevent.
		var token = CreateToken(new Dictionary<string, object> { ["client_id"] = ApiAudience });

		var result = await AuthenticateAsync(
			TenantConfig(audienceClaim: "client_id", requiredClaims: null), token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Tenant configuration is invalid");
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public async Task A_blank_configured_audience_never_matches_a_blank_token_audience(string blank) {
		// The blank-value escape: a tenant record carrying an empty audience string would match a
		// token presenting an empty one, turning a missing configuration into an acceptance. Both
		// sides are blank here, so anything that compares them without checking would let it pass.
		var token = CreateToken(new Dictionary<string, object> {
			["token_use"] = "access",
			["client_id"] = blank
		});

		var result = await AuthenticateAsync(
			TenantConfig(
				audienceClaim: "client_id",
				requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" },
				validAudiences: [blank]),
			token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Tenant configuration is invalid");
	}

	[Fact]
	public async Task A_tenant_with_no_configured_audiences_authenticates_no_one() {
		var token = CreateToken(new Dictionary<string, object> { ["aud"] = ApiAudience });

		var result = await AuthenticateAsync(TenantConfig(validAudiences: []), token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Tenant configuration is invalid");
	}

	[Fact]
	public async Task A_blank_token_audience_is_rejected_against_a_real_configured_audience() {
		var token = CreateToken(new Dictionary<string, object> {
			["token_use"] = "access",
			["client_id"] = ""
		});

		var result = await AuthenticateAsync(
			TenantConfig(
				audienceClaim: "client_id",
				requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" }),
			token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("audience");
	}

	[Fact]
	public async Task A_required_claim_with_the_wrong_value_is_rejected() {
		// The Cognito shape: an ID token reaching an API that expects an access token.
		var token = CreateToken(new Dictionary<string, object> {
			["token_use"] = "id",
			["aud"] = ApiAudience
		});

		var result = await AuthenticateAsync(
			TenantConfig(requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" }),
			token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("token_use");
	}

	[Fact]
	public async Task A_required_claim_that_is_absent_is_rejected() {
		var token = CreateToken(new Dictionary<string, object> { ["aud"] = ApiAudience });

		var result = await AuthenticateAsync(
			TenantConfig(requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" }),
			token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("token_use");
	}

	[Fact]
	public async Task A_relocated_audience_is_validated_against_the_same_valid_audiences() {
		// `aud` holds a value that would pass if the relocation were ignored, while the claim the
		// tenant actually nominated holds a different one. Standard audience validation is off for
		// this tenant, so if the explicit check did not run, this token would be accepted.
		var token = CreateToken(new Dictionary<string, object> {
			["token_use"] = "access",
			["aud"] = ApiAudience,
			["client_id"] = "https://some-other-api.example.com"
		});

		var result = await AuthenticateAsync(
			TenantConfig(
				audienceClaim: "client_id",
				requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" }),
			token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("audience");
	}

	// -------------------------------------------------------------------------
	// Reserved claims — these run the full validation path
	// -------------------------------------------------------------------------

	[Fact]
	public async Task A_token_supplied_tenant_slug_cannot_shadow_the_resolved_one() {
		// tenant_slug describes which tenant the framework resolved. Appending ours to an identity
		// that already carries one from the token leaves two, and FindFirst returns the token's
		// because it was added first — a tenant-spoofing primitive on the multi-tenant boundary.
		var token = CreateToken(new Dictionary<string, object> {
			["aud"] = ApiAudience,
			["sub"] = "user-1",
			[ExternalClaimTypes.TenantSlug] = "attacker-tenant"
		});

		var result = await AuthenticateAsync(TenantConfig(), token, new StubConfigurationManager());

		result.Succeeded.Should().BeTrue();
		result.Principal!.FindAll(ExternalClaimTypes.TenantSlug)
			.Should().ContainSingle().Which.Value.Should().Be(Slug);
	}

	[Fact]
	public async Task A_claim_mapping_cannot_target_a_reserved_claim() {
		// The mapping target is tenant-controlled data, so it is a second route to the same shadowing.
		var token = CreateToken(new Dictionary<string, object> {
			["aud"] = ApiAudience,
			["sub"] = "user-1",
			["groups"] = "attacker-tenant"
		});

		var tenantConfig = TenantConfig() with {
			ClaimMappings = new Dictionary<string, string> { ["groups"] = ExternalClaimTypes.TenantSlug }
		};

		var result = await AuthenticateAsync(tenantConfig, token, new StubConfigurationManager());

		result.Succeeded.Should().BeTrue();
		result.Principal!.FindAll(ExternalClaimTypes.TenantSlug)
			.Should().ContainSingle().Which.Value.Should().Be(Slug);
	}

	[Fact]
	public async Task An_array_valued_audience_validates() {
		// `aud` may be a string or an array (RFC 7519 §4.1.3). Reading it as a string alone reports a
		// valid multi-audience token as carrying no audience at all.
		var token = CreateToken(new Dictionary<string, object> {
			["aud"] = new[] { "https://other-api.example.com", ApiAudience },
			["sub"] = "user-1"
		});

		var result = await AuthenticateAsync(TenantConfig(), token, new StubConfigurationManager());

		result.Succeeded.Should().BeTrue();
	}

	[Fact]
	public async Task An_array_valued_relocated_audience_validates() {
		var token = CreateToken(new Dictionary<string, object> {
			["token_use"] = "access",
			["sub"] = "user-1",
			["aud"] = ApiAudience,
			["client_id"] = new[] { "https://other-api.example.com", ApiAudience }
		});

		var result = await AuthenticateAsync(
			TenantConfig(
				audienceClaim: "client_id",
				requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" }),
			token,
			new StubConfigurationManager());

		result.Succeeded.Should().BeTrue(result.Failure?.Message ?? "(no failure recorded)");
	}

	[Fact]
	public async Task A_blank_required_claim_type_is_a_misconfiguration() {
		var token = CreateToken(new Dictionary<string, object> { ["aud"] = ApiAudience });

		var result = await AuthenticateAsync(
			TenantConfig(requiredClaims: new Dictionary<string, string> { ["  "] = "access" }), token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Tenant configuration is invalid");
	}

	[Fact]
	public async Task A_relocated_audience_that_matches_proceeds_past_the_pre_checks() {
		// Reaching outbound metadata retrieval is the success condition here: the pre-checks passed
		// and the request moved on to signature validation, which is where a token is actually
		// trusted. The stub throws there, and the handler turns that into its own failure message —
		// which is what distinguishes "got through the pre-checks" from every case above.
		var token = CreateToken(new Dictionary<string, object> {
			["token_use"] = "access",
			["client_id"] = ApiAudience
		});

		var result = await AuthenticateAsync(
			TenantConfig(
				audienceClaim: "client_id",
				requiredClaims: new Dictionary<string, string> { ["token_use"] = "access" }),
			token);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Failed to retrieve IdP configuration");
	}
}
