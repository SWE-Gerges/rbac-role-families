using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Rbac.Abstractions;
using Rbac.AspNetCore.Claims;
using Rbac.AspNetCore.Http;
using Rbac.Core.Catalog;
using Shouldly;
using Xunit;

namespace Rbac.Tests.AspNetCore;

public class OnBehalfMiddlewareTests
{
    private static readonly PrincipalFactory Principals = new(DefaultRoleCatalog.Create());

    private readonly IEffectivePrincipalResolver _resolver = Substitute.For<IEffectivePrincipalResolver>();
    private readonly IProblemDetailsService _problems = Substitute.For<IProblemDetailsService>();
    private bool _nextCalled;

    private OnBehalfMiddleware Middleware() => new(_ =>
    {
        _nextCalled = true;
        return Task.CompletedTask;
    });

    private static DefaultHttpContext Context(string? header, bool authenticated = true)
    {
        var context = new DefaultHttpContext();
        if (header is not null)
        {
            context.Request.Headers[OnBehalfMiddleware.HeaderName] = header;
        }

        if (authenticated)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(RbacClaimTypes.Subject, "actor"),
                    new Claim(RbacClaimTypes.TenantId, "t1"),
                    new Claim(RbacClaimTypes.Role, RoleKeys.SystemAdmin),
                    new Claim(RbacClaimTypes.TokenVersion, "1"),
                ],
                authenticationType: "test"));
        }

        return context;
    }

    [Fact]
    public async Task Without_the_header_or_without_authentication_the_request_passes_untouched()
    {
        await Middleware().InvokeAsync(Context(header: null), Principals, _resolver, _problems);
        _nextCalled.ShouldBeTrue();

        _nextCalled = false;
        await Middleware().InvokeAsync(Context("someone", authenticated: false), Principals, _resolver, _problems);
        _nextCalled.ShouldBeTrue("authorization answers 401 later");

        await _resolver.DidNotReceiveWithAnyArgs().ResolveAsync(default!, default!, default);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a b")]
    [InlineData("a,b")]
    public async Task A_malformed_header_is_a_400_and_nothing_is_resolved(string header)
    {
        var context = Context(header);

        await Middleware().InvokeAsync(context, Principals, _resolver, _problems);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        _nextCalled.ShouldBeFalse();
        await _resolver.DidNotReceiveWithAnyArgs().ResolveAsync(default!, default!, default);
    }

    [Theory]
    [InlineData(OnBehalfFailure.MissingPermission, StatusCodes.Status403Forbidden)]
    [InlineData(OnBehalfFailure.NotAllowed, StatusCodes.Status403Forbidden)]
    [InlineData(OnBehalfFailure.NotFound, StatusCodes.Status404NotFound)]
    public async Task A_refusal_stops_the_request_with_its_status(OnBehalfFailure failure, int status)
    {
        _resolver.ResolveAsync(Arg.Any<Principal>(), "target", Arg.Any<CancellationToken>()).Returns(EffectivePrincipalResult.Fail(failure, "why"));
        var context = Context("target");

        await Middleware().InvokeAsync(context, Principals, _resolver, _problems);

        context.Response.StatusCode.ShouldBe(status);
        _nextCalled.ShouldBeFalse();
        context.Items.ContainsKey(OnBehalfMiddleware.PrincipalItemKey).ShouldBeFalse();
    }

    [Fact]
    public async Task Success_stores_the_effective_principal_for_the_rest_of_the_request_and_the_resolver_sees_the_actor()
    {
        var effective = Principal.ForStaff("target", "t1", RoleKeys.AgencyStaff, "ag1") with { ActingUser = "actor" };
        _resolver.ResolveAsync(Arg.Any<Principal>(), "target", Arg.Any<CancellationToken>()).Returns(EffectivePrincipalResult.Success(effective));
        var context = Context(" target ");

        await Middleware().InvokeAsync(context, Principals, _resolver, _problems);

        _nextCalled.ShouldBeTrue();
        context.Items[OnBehalfMiddleware.PrincipalItemKey].ShouldBe(effective);
        await _resolver.Received(1).ResolveAsync(
            Arg.Is<Principal>(p => p.UserId == "actor" && p.RoleKey == RoleKeys.SystemAdmin && !p.IsOnBehalf),
            "target",
            Arg.Any<CancellationToken>());
        effective.IsOnBehalf.ShouldBeTrue();
        effective.ActingUserId.ShouldBe("actor");
        effective.EffectiveUserId.ShouldBe("target");
    }
}
