using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class OperationalTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Liveness_and_readiness_are_anonymous_and_readiness_checks_the_database()
    {
        using var client = factory.CreateClient();

        var live = await client.GetAsync("/health/live");
        var ready = await client.GetAsync("/health/ready");

        live.StatusCode.ShouldBe(HttpStatusCode.OK);
        ready.StatusCode.ShouldBe(HttpStatusCode.OK);
        var body = await ready.ReadJsonAsync();
        body.GetProperty("status").GetString().ShouldBe("Healthy");
        body.GetProperty("checks").GetProperty("database").GetString().ShouldBe("Healthy");
        (await live.ReadJsonAsync()).GetProperty("checks").EnumerateObject().ShouldBeEmpty();
    }

    [Fact]
    public async Task Readiness_is_503_when_a_dependency_check_fails_while_liveness_stays_200_and_the_reason_is_not_leaked()
    {
        using var broken = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddHealthChecks().AddCheck(
                "broken-dependency",
                () => HealthCheckResult.Unhealthy("connection string is hunter2", new InvalidOperationException("secret detail")),
                tags: ["ready"])));
        using var client = broken.CreateClient();

        var ready = await client.GetAsync("/health/ready");
        var live = await client.GetAsync("/health/live");

        ready.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        live.StatusCode.ShouldBe(HttpStatusCode.OK);
        var text = await ready.Content.ReadAsStringAsync();
        text.ShouldContain("broken-dependency");
        text.ShouldNotContain("hunter2");
        text.ShouldNotContain("secret detail");
        (await ready.ReadJsonAsync()).GetProperty("status").GetString().ShouldBe("Unhealthy");
    }

    [Fact]
    public async Task A_correlation_id_is_generated_when_absent_and_echoed_when_supplied()
    {
        using var client = factory.CreateClient();

        var generated = await client.GetAsync("/health/live");
        var echoed = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/health/live") { Headers = { { "X-Correlation-Id", "trace-123.abc" } } });

        generated.Headers.GetValues("X-Correlation-Id").Single().Length.ShouldBeGreaterThan(8);
        echoed.Headers.GetValues("X-Correlation-Id").Single().ShouldBe("trace-123.abc");
    }

    [Fact]
    public async Task An_unsafe_correlation_id_is_replaced_not_echoed()
    {
        using var client = factory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "/health/live");
        request.Headers.TryAddWithoutValidation("X-Correlation-Id", "<script>alert(1)</script>");

        var response = await client.SendAsync(request);

        var id = response.Headers.GetValues("X-Correlation-Id").Single();
        id.ShouldNotContain("<");
        id.Length.ShouldBeLessThanOrEqualTo(64);
    }

    [Fact]
    public async Task Problem_responses_carry_the_correlation_id_and_follow_rfc_7807()
    {
        using var client = await factory.ClientForAsync(SeedIds.AgencyStaffA);
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/bookings/bk-a-001");
        request.Headers.Add("X-Correlation-Id", "corr-42");

        var response = await client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType!.MediaType.ShouldBe("application/problem+json");
        var problem = await response.ReadJsonAsync();
        problem.GetProperty("status").GetInt32().ShouldBe(404);
        problem.GetProperty("title").GetString().ShouldNotBeNullOrEmpty();
        problem.GetProperty("correlationId").GetString().ShouldBe("corr-42");
        response.Headers.GetValues("X-Correlation-Id").Single().ShouldBe("corr-42");
    }

    [Fact]
    public async Task The_status_codes_for_missing_authentication_and_permission_are_401_and_403_problem_documents()
    {
        using var anonymous = factory.CreateClient();
        using var viewer = await factory.ClientForAsync(SeedIds.ReportViewerA);

        var unauthorized = await anonymous.GetAsync("/api/v1/bookings");
        var forbidden = await viewer.GetAsync("/api/v1/bookings");

        unauthorized.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        forbidden.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        foreach (var response in new[] { unauthorized, forbidden })
        {
            MatrixRunner.IsProblem(response).ShouldBeTrue();
            (await response.ReadJsonAsync()).TryGetProperty("correlationId", out _).ShouldBeTrue();
        }
    }

    [Fact]
    public async Task An_unhandled_exception_is_a_generic_500_problem_with_no_message_or_stack_trace()
    {
        const string secret = "super-secret-internal-detail";
        using var throwing = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddTransient<IStartupFilter>(_ => new ThrowingStartupFilter(secret))));
        using var client = throwing.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", ForgedTokens.Staff(SeedIds.SystemAdminA, SeedIds.TenantA, "system-admin"));

        var response = await client.GetAsync("/boom");

        response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
        var text = await response.Content.ReadAsStringAsync();
        text.ShouldNotContain(secret);
        text.ShouldNotContain("InvalidOperationException");
        text.ShouldNotContain("   at ");
        text.ShouldNotContain(".cs");
        (await response.ReadJsonAsync()).GetProperty("title").GetString().ShouldBe("An unexpected error occurred.");
    }

    [Fact]
    public async Task The_dev_token_endpoint_issues_a_working_token_for_every_seeded_user()
    {
        foreach (var user in DemoSeedData.Users)
        {
            using var client = factory.CreateClient();

            var response = await client.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(user.Id), ApiFactory.Json);

            response.StatusCode.ShouldBe(HttpStatusCode.OK, user.Id);
            var token = await response.ReadAsAsync<DevTokenResponse>();
            token.TokenType.ShouldBe("Bearer");
            token.TenantId.ShouldBe(user.TenantId);
            token.RoleKey.ShouldBe(user.RoleKey);
            token.ExpiresAt.ShouldBeGreaterThan(DateTimeOffset.UtcNow);

            using var authed = factory.ClientWithToken(token.AccessToken);
            (await authed.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK, user.Id);
        }
    }

    [Theory]
    [InlineData("""{"userId":"nobody"}""", HttpStatusCode.NotFound)]
    [InlineData("""{"userId":""}""", HttpStatusCode.BadRequest)]
    [InlineData("""{"userId":"  "}""", HttpStatusCode.BadRequest)]
    [InlineData("""{}""", HttpStatusCode.BadRequest)]
    public async Task The_dev_token_endpoint_rejects_unknown_and_missing_users(string body, HttpStatusCode expected)
    {
        using var client = factory.CreateClient();

        var response = await client.PostAsync("/api/v1/dev/token", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(expected);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
    }

    [Fact]
    public async Task The_dev_token_endpoint_does_not_exist_unless_it_is_explicitly_enabled()
    {
        using var disabled = ApiFactory.With(new ApiFactoryOptions { EnableDevTokens = false });
        using var anonymous = disabled.CreateClient();
        using var authenticated = disabled.ClientWithToken(ForgedTokens.Staff(SeedIds.SystemAdminA, SeedIds.TenantA, "system-admin"));

        // Anonymous callers are turned away by the deny-by-default fallback; callers with a token learn the route is not there.
        var anonymousResponse = await anonymous.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(SeedIds.SystemAdminA), ApiFactory.Json);
        var authenticatedResponse = await authenticated.PostAsJsonAsync("/api/v1/dev/token", new DevTokenRequest(SeedIds.SystemAdminA), ApiFactory.Json);

        anonymousResponse.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        authenticatedResponse.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await anonymous.GetAsync("/health/live")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await (await authenticated.GetAsync("/openapi/v1.json")).Content.ReadAsStringAsync()).ShouldNotContain("/dev/token");
    }

    private sealed class ThrowingStartupFilter(string message) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            next(app);
            app.Use((HttpContext context, RequestDelegate _) => context.Request.Path == "/boom"
                ? throw new InvalidOperationException(message)
                : Task.CompletedTask);
        };
    }
}
