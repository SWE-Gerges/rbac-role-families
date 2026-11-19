using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using NSubstitute;
using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.AspNetCore.Http;
using Rbac.Core.Catalog;
using Shouldly;
using Xunit;

namespace Rbac.Tests.AspNetCore;

public class AuthorizationTests
{
    private static PermissionPolicyProvider Provider() => new(Options.Create(new AuthorizationOptions()));

    [Fact]
    public async Task A_permission_policy_is_built_on_demand_with_a_permission_requirement()
    {
        var policy = await Provider().GetPolicyAsync(PermissionPolicy.NameFor(Permissions.BookingsCancel));

        policy.ShouldNotBeNull();
        policy.Requirements.OfType<PermissionRequirement>().Single().Permission.ShouldBe(Permissions.BookingsCancel);
        policy.Requirements.ShouldContain(r => r is Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task The_same_permission_yields_the_same_cached_policy()
    {
        var provider = Provider();

        var first = await provider.GetPolicyAsync(PermissionPolicy.NameFor(Permissions.ReportsView));
        var second = await provider.GetPolicyAsync(PermissionPolicy.NameFor(Permissions.ReportsView));

        second.ShouldBeSameAs(first);
    }

    [Fact]
    public async Task Other_policy_names_are_left_to_the_default_provider()
    {
        var provider = new PermissionPolicyProvider(Options.Create(new AuthorizationOptions()));

        (await provider.GetPolicyAsync("something-else")).ShouldBeNull();
    }

    [Fact]
    public async Task The_fallback_policy_comes_from_the_authorization_options()
    {
        var fallback = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        var provider = new PermissionPolicyProvider(Options.Create(new AuthorizationOptions { FallbackPolicy = fallback }));

        (await provider.GetFallbackPolicyAsync()).ShouldBeSameAs(fallback);
    }

    [Fact]
    public void The_attribute_maps_to_the_policy_name()
    {
        var attribute = new RequirePermissionAttribute(Permissions.UsersCreate);

        attribute.Policy.ShouldBe(PermissionPolicy.NameFor(Permissions.UsersCreate));
        PermissionPolicy.TryGetPermission(attribute.Policy!, out var permission).ShouldBeTrue();
        permission.ShouldBe(Permissions.UsersCreate);
        PermissionPolicy.TryGetPermission("permission:", out _).ShouldBeFalse();
        PermissionPolicy.TryGetPermission("other", out _).ShouldBeFalse();
    }

    [Theory]
    [InlineData(Permissions.BookingsCancel, true)]
    [InlineData(Permissions.UsersCreate, false)]
    public async Task The_handler_succeeds_only_when_the_live_permissions_contain_the_requirement(string required, bool expected)
    {
        var permissions = Substitute.For<ICurrentPermissions>();
        permissions.GetAsync(Arg.Any<CancellationToken>()).Returns(new ValueTask<PermissionSet>(PermissionSet.Create(Permissions.BookingsCancel)));
        var handler = new PermissionAuthorizationHandler(permissions);
        var requirement = new PermissionRequirement(required);
        var context = new AuthorizationHandlerContext([requirement], new System.Security.Claims.ClaimsPrincipal(), resource: null);

        await handler.HandleAsync(context);

        context.HasSucceeded.ShouldBe(expected);
        context.HasFailed.ShouldBeFalse("a missing permission is a plain denial, not an explicit failure");
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("abc-123", true)]
    [InlineData("a.b_c:d-9", true)]
    [InlineData("has space", false)]
    [InlineData("new\nline", false)]
    [InlineData("<script>", false)]
    public void Only_short_safe_correlation_ids_are_accepted(string? candidate, bool accepted)
    {
        (CorrelationIdMiddleware.Accept(candidate) is not null).ShouldBe(accepted);
    }

    [Fact]
    public void A_correlation_id_longer_than_64_characters_is_rejected()
    {
        CorrelationIdMiddleware.Accept(new string('a', 64)).ShouldNotBeNull();
        CorrelationIdMiddleware.Accept(new string('a', 65)).ShouldBeNull();
    }
}
