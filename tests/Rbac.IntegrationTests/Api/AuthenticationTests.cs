using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Catalog;
using Rbac.Demo.Contracts;
using Rbac.IntegrationTests.Support;
using Rbac.Persistence.Seeding;
using Shouldly;
using Xunit;

namespace Rbac.IntegrationTests.Api;

[Trait("Category", "Integration")]
public class AuthenticationTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;

    public AuthenticationTests(ApiFactory factory) => _factory = factory;

    public static TheoryData<string, string> ProtectedEndpoints => new()
    {
        { "GET", "/api/v1/me" },
        { "GET", "/api/v1/bookings" },
        { "GET", "/api/v1/bookings/bk-a-001" },
        { "POST", "/api/v1/bookings" },
        { "POST", "/api/v1/bookings/bk-a-001/cancel" },
        { "GET", "/api/v1/access-matrix" },
        { "GET", "/openapi/v1.json" },
    };

    [Theory]
    [MemberData(nameof(ProtectedEndpoints))]
    public async Task Every_protected_endpoint_returns_401_for_an_anonymous_caller(string method, string path)
    {
        using var client = _factory.CreateClient();

        var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
        response.Headers.WwwAuthenticate.Single().Scheme.ShouldBe("Bearer");
    }

    [Fact]
    public async Task Unknown_routes_are_not_served_to_anonymous_callers_either_but_stay_a_clean_404()
    {
        using var client = await _factory.ClientForAsync(SeedIds.SystemAdminA);

        var response = await client.GetAsync("/api/v1/nope");

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        MatrixRunner.IsProblem(response).ShouldBeTrue();
    }

    [Fact]
    public async Task Only_health_checks_and_the_dev_token_issuer_allow_anonymous_access()
    {
        var endpoints = _factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToArray();

        var anonymous = endpoints
            .Where(e => e.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            .Select(e => e.RoutePattern.RawText)
            .Order()
            .ToArray();

        anonymous.ShouldBe(["/api/v1/dev/token", "/health/live", "/health/ready"]);
        endpoints.Length.ShouldBeGreaterThan(8);

        var fallback = await _factory.Services.GetRequiredService<IAuthorizationPolicyProvider>().GetFallbackPolicyAsync();
        fallback.ShouldNotBeNull("deny by default needs a fallback policy");
        fallback.Requirements.ShouldContain(r => r is Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public void Each_gated_endpoint_declares_the_permission_it_needs()
    {
        var endpoints = _factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>();

        var gated = endpoints
            .SelectMany(e => e.Metadata.OfType<RequirePermissionAttribute>().Select(a => (Route: $"{e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Single()} {e.RoutePattern.RawText!.TrimEnd('/')}", a.Permission)))
            .OrderBy(x => x.Route, StringComparer.Ordinal)
            .ToArray();

        gated.ShouldBe(
        [
            ("DELETE /api/v1/users/{id}", Permissions.UsersManage),
            ("GET /api/v1/access-matrix", Permissions.AccessMatrixView),
            ("GET /api/v1/audit", Permissions.AuditView),
            ("GET /api/v1/bookings", Permissions.BookingsRead),
            ("GET /api/v1/bookings/{id}", Permissions.BookingsRead),
            ("GET /api/v1/permissions", Permissions.PermissionsView),
            ("GET /api/v1/roles", Permissions.PermissionsView),
            ("GET /api/v1/roles/{key}", Permissions.PermissionsView),
            ("GET /api/v1/users", Permissions.UsersRead),
            ("GET /api/v1/users/{id}", Permissions.UsersRead),
            ("GET /api/v1/users/{id}/permissions", Permissions.PermissionsView),
            ("POST /api/v1/bookings", Permissions.BookingsCreate),
            ("POST /api/v1/bookings/{id}/cancel", Permissions.BookingsCancel),
            ("POST /api/v1/users", Permissions.UsersCreate),
            ("PUT /api/v1/roles/{key}/permissions", Permissions.RolesManagePermissions),
            ("PUT /api/v1/users/{id}/permissions", Permissions.UsersManage),
            ("PUT /api/v1/users/{id}/role", Permissions.UsersManage),
        ]);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("a.b.c")]
    public async Task A_malformed_token_is_a_401(string token)
    {
        using var client = _factory.ClientWithToken(token);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_token_signed_with_another_key_is_a_401()
    {
        var token = ForgedTokens.Create(
            [new Claim("sub", "u"), new Claim("tenant_id", "t"), new Claim("token_version", "1")],
            signingKey: "some-other-signing-key-0123456789abcdef");
        using var client = _factory.ClientWithToken(token);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_token_for_another_audience_or_issuer_is_a_401()
    {
        Claim[] claims = [new("sub", SeedIds.SystemAdminA), new("tenant_id", SeedIds.TenantA), new("role", RoleKeys.SystemAdmin), new("token_version", "1")];

        using var wrongAudience = _factory.ClientWithToken(ForgedTokens.Create(claims, audience: "someone-else"));
        using var wrongIssuer = _factory.ClientWithToken(ForgedTokens.Create(claims, issuer: "someone-else"));

        (await wrongAudience.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await wrongIssuer.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task An_expired_token_is_a_401()
    {
        var token = ForgedTokens.Create(
            [new Claim("sub", SeedIds.SystemAdminA), new Claim("tenant_id", SeedIds.TenantA), new Claim("role", RoleKeys.SystemAdmin), new Claim("token_version", "1")],
            notBefore: DateTime.UtcNow.AddHours(-3),
            expires: DateTime.UtcNow.AddHours(-2));
        using var client = _factory.ClientWithToken(token);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_token_without_a_version_claim_is_a_401()
    {
        var token = ForgedTokens.Create(
            [new Claim("sub", SeedIds.SystemAdminA), new Claim("tenant_id", SeedIds.TenantA), new Claim("role", RoleKeys.SystemAdmin)]);
        using var client = _factory.ClientWithToken(token);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Only_the_bearer_scheme_is_accepted()
    {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String("admin:admin"u8.ToArray()));

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_signed_token_for_a_user_whose_token_version_is_stale_is_a_401_not_a_403()
    {
        var token = ForgedTokens.Staff(SeedIds.AgencyStaffA, SeedIds.TenantA, RoleKeys.AgencyStaff, SeedIds.AgencyA1, version: 7);
        using var client = _factory.ClientWithToken(token);

        (await client.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Bumping_the_token_version_revokes_existing_sessions_and_a_new_token_works()
    {
        var versions = _factory.Services.GetRequiredService<ITokenVersionStore>();
        const string user = SeedIds.InternalAdminB;
        using var before = await _factory.ClientForAsync(user, freshToken: true);
        (await before.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await versions.BumpAsync(SeedIds.TenantB, user, CancellationToken.None);

        var revoked = await before.GetAsync("/api/v1/bookings");
        revoked.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        MatrixRunner.IsProblem(revoked).ShouldBeTrue();

        using var after = await _factory.ClientForAsync(user, freshToken: true);
        var me = await (await after.GetAsync("/api/v1/me")).ReadAsAsync<MeResponse>();
        me.TokenVersion.ShouldBe(2);
        (await after.GetAsync("/api/v1/bookings")).StatusCode.ShouldBe(HttpStatusCode.OK);

        using var otherUser = await _factory.ClientForAsync(SeedIds.InternalStaffB);
        (await otherUser.GetAsync("/api/v1/me")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }
}
