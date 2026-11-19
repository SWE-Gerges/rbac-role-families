using System.Security.Claims;
using Rbac.Abstractions;
using Rbac.AspNetCore.Claims;
using Rbac.Core.Catalog;
using Shouldly;
using Xunit;

namespace Rbac.Tests.AspNetCore;

public class PrincipalFactoryTests
{
    private readonly PrincipalFactory _factory = new(DefaultRoleCatalog.Create());

    private static ClaimsPrincipal Authenticated(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), authenticationType: "test"));

    [Fact]
    public void A_complete_staff_token_becomes_a_staff_principal()
    {
        var principal = _factory.Create(Authenticated(
            (RbacClaimTypes.Subject, "u1"),
            (RbacClaimTypes.TenantId, "t1"),
            (RbacClaimTypes.Role, RoleKeys.AgencyStaff),
            (RbacClaimTypes.AgencyId, "ag1"),
            (RbacClaimTypes.TokenVersion, "3")));

        principal.ShouldBe(Principal.ForStaff("u1", "t1", RoleKeys.AgencyStaff, "ag1", null, 3));
    }

    [Fact]
    public void A_customer_token_becomes_a_customer_and_ignores_staff_claims()
    {
        var principal = _factory.Create(Authenticated(
            (RbacClaimTypes.Subject, "c1"),
            (RbacClaimTypes.TenantId, "t1"),
            (RbacClaimTypes.PrincipalKind, RbacClaimTypes.CustomerKind),
            (RbacClaimTypes.Role, RoleKeys.SystemAdmin),
            (RbacClaimTypes.AgencyId, "ag1"),
            (RbacClaimTypes.TokenVersion, "1")));

        principal.ShouldBe(Principal.ForCustomer("c1", "t1"));
        principal.RoleKey.ShouldBeNull();
        principal.AgencyId.ShouldBeNull();
    }

    [Fact]
    public void An_unauthenticated_user_is_anonymous()
    {
        _factory.Create(new ClaimsPrincipal(new ClaimsIdentity())).ShouldBe(Principal.Anonymous);
        _factory.Create(null).ShouldBe(Principal.Anonymous);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-role")]
    [InlineData("Agency-Staff")]
    public void A_missing_or_unknown_role_is_anonymous_never_a_default_role(string? role)
    {
        var claims = new List<(string, string)>
        {
            (RbacClaimTypes.Subject, "u1"),
            (RbacClaimTypes.TenantId, "t1"),
            (RbacClaimTypes.TokenVersion, "1"),
        };
        if (role is not null)
        {
            claims.Add((RbacClaimTypes.Role, role));
        }

        _factory.Create(Authenticated([.. claims])).ShouldBe(Principal.Anonymous);
    }

    [Theory]
    [InlineData(RbacClaimTypes.Subject)]
    [InlineData(RbacClaimTypes.TenantId)]
    public void A_missing_subject_or_tenant_is_anonymous(string missing)
    {
        var all = new Dictionary<string, string>
        {
            [RbacClaimTypes.Subject] = "u1",
            [RbacClaimTypes.TenantId] = "t1",
            [RbacClaimTypes.Role] = RoleKeys.SystemAdmin,
            [RbacClaimTypes.TokenVersion] = "1",
        };
        all.Remove(missing);

        _factory.Create(Authenticated([.. all.Select(kv => (kv.Key, kv.Value))])).ShouldBe(Principal.Anonymous);
    }

    [Fact]
    public void An_unrecognised_principal_kind_is_anonymous()
    {
        var principal = _factory.Create(Authenticated(
            (RbacClaimTypes.Subject, "u1"),
            (RbacClaimTypes.TenantId, "t1"),
            (RbacClaimTypes.Role, RoleKeys.SystemAdmin),
            (RbacClaimTypes.PrincipalKind, "service")));

        principal.ShouldBe(Principal.Anonymous);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("abc")]
    [InlineData("-1")]
    public void A_missing_or_malformed_token_version_maps_to_zero_which_never_matches_a_real_version(string? version)
    {
        var claims = new List<(string, string)>
        {
            (RbacClaimTypes.Subject, "u1"),
            (RbacClaimTypes.TenantId, "t1"),
            (RbacClaimTypes.Role, RoleKeys.SystemAdmin),
        };
        if (version is not null)
        {
            claims.Add((RbacClaimTypes.TokenVersion, version));
        }

        _factory.Create(Authenticated([.. claims])).TokenVersion.ShouldBe(0);
    }

    [Fact]
    public void Claims_and_principals_round_trip()
    {
        Principal[] principals =
        [
            Principal.ForStaff("u1", "t1", RoleKeys.AgencyAdmin, "ag1", null, 4),
            Principal.ForStaff("u2", "t1", RoleKeys.CorporateStaff, null, "co1", 2),
            Principal.ForStaff("u3", "t2", RoleKeys.SystemAdmin),
            Principal.ForCustomer("c1", "t1", 5),
        ];

        foreach (var principal in principals)
        {
            var identity = new ClaimsIdentity(PrincipalClaims.ToClaims(principal), "test");

            _factory.Create(new ClaimsPrincipal(identity)).ShouldBe(principal);
        }
    }

    [Fact]
    public void An_anonymous_principal_produces_no_claims()
    {
        PrincipalClaims.ToClaims(Principal.Anonymous).ShouldBeEmpty();
    }
}
