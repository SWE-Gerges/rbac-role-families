using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Rbac.Abstractions;
using Rbac.AspNetCore.Claims;

namespace Rbac.AspNetCore.Http;

/// <summary>
/// Reads <c>X-On-Behalf-Of</c> and, when the caller is allowed to act as that user, replaces the request's principal with the
/// effective one before authorization runs, so every permission check and scope uses the effective user. A caller who is not
/// allowed gets a refusal; the header is never ignored silently. Unauthenticated requests are left alone and fail as 401 later.
/// </summary>
public sealed partial class OnBehalfMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-On-Behalf-Of";

    /// <summary>The key under which the effective principal is stored for the rest of the request.</summary>
    public const string PrincipalItemKey = "Rbac.EffectivePrincipal";

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    private static partial Regex UserIdPattern();

    public async Task InvokeAsync(
        HttpContext context,
        PrincipalFactory principals,
        IEffectivePrincipalResolver resolver,
        IProblemDetailsService problems)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Headers.TryGetValue(HeaderName, out var header) || context.User.Identity?.IsAuthenticated != true)
        {
            await next(context);
            return;
        }

        var actor = principals.Create(context.User);
        if (actor.IsAnonymous)
        {
            await next(context);
            return;
        }

        var target = header.Count == 1 ? header[0]?.Trim() : null;
        if (target is null || !UserIdPattern().IsMatch(target))
        {
            await WriteAsync(context, problems, StatusCodes.Status400BadRequest, "Invalid X-On-Behalf-Of header.", "Send exactly one user id.");
            return;
        }

        var result = await resolver.ResolveAsync(actor, target, context.RequestAborted);
        if (result.Principal is { } effective)
        {
            context.Items[PrincipalItemKey] = effective;
            await next(context);
            return;
        }

        var (status, title, detail) = result.Failure switch
        {
            OnBehalfFailure.MissingPermission => (StatusCodes.Status403Forbidden, "Acting on behalf of another user is not allowed.", result.Detail),
            OnBehalfFailure.NotAllowed => (StatusCodes.Status403Forbidden, "You cannot act as that user.", result.Detail),
            _ => (StatusCodes.Status404NotFound, "User not found.", "The user does not exist or is not visible to the caller."),
        };
        await WriteAsync(context, problems, status, title, detail);
    }

    private static async Task WriteAsync(HttpContext context, IProblemDetailsService problems, int status, string title, string? detail)
    {
        context.Response.StatusCode = status;
        await problems.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = new ProblemDetails { Status = status, Title = title, Detail = detail },
        });
    }
}

public static class OnBehalfExtensions
{
    /// <summary>Add it after authentication and before authorization.</summary>
    public static IApplicationBuilder UseOnBehalf(this IApplicationBuilder app) => app.UseMiddleware<OnBehalfMiddleware>();
}
