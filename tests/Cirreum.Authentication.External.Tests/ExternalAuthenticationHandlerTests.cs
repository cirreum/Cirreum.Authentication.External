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

	private static string CreateToken(Dictionary<string, object> claims, string? tokenType = null) {
		var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('k', 64)));
		return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor {
			Issuer = Issuer,
			Claims = claims,
			TokenType = tokenType,
			SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
		});
	}

	private static ExternalTenantConfig TenantConfig(
		string audienceClaim = ExternalDefaults.DefaultAudienceClaim,
		IReadOnlyDictionary<string, string>? requiredClaims = null) =>
		new() {
			Slug = Slug,
			IsEnabled = true,
			MetadataAddress = $"{Issuer}.well-known/openid-configuration",
			ValidAudiences = [ApiAudience],
			AudienceClaim = audienceClaim,
			RequiredClaims = requiredClaims
		};

	private static async Task<AuthenticateResult> AuthenticateAsync(
		ExternalTenantConfig tenantConfig,
		string token) {

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
			new UnreachableConfigurationManager(),
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
