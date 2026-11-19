using Rbac.Persistence.Administration;

namespace Rbac.Demo.Endpoints;

internal static class AdminResultMapping
{
    /// <summary>Maps an administrative outcome to its HTTP response. The 404 body is the same for "missing" and "not visible".</summary>
    public static IResult ToHttp<T>(this AdminResult<T> result, Func<T, IResult> onOk, Func<T, IResult>? onCreated = null) => result.Outcome switch
    {
        AdminOutcome.Ok => onOk(result.Value!),
        AdminOutcome.Created => (onCreated ?? onOk)(result.Value!),
        AdminOutcome.NoContent => Results.NoContent(),
        AdminOutcome.Invalid => Results.ValidationProblem(result.Errors ?? new Dictionary<string, string[]>()),
        AdminOutcome.Forbidden => Problem(StatusCodes.Status403Forbidden, "The operation is not allowed.", result.Message),
        AdminOutcome.NotFound => NotFound(),
        AdminOutcome.Conflict => Problem(StatusCodes.Status409Conflict, "Conflict.", result.Message),
        AdminOutcome.PreconditionFailed => Problem(
            StatusCodes.Status412PreconditionFailed,
            "The resource changed.",
            result.Message ?? "The If-Match version is out of date. Read the resource again and retry."),
        AdminOutcome.PreconditionRequired => Problem(
            StatusCodes.Status428PreconditionRequired,
            "A precondition is required.",
            result.Message ?? "Send the version you read in an If-Match header."),
        _ => throw new InvalidOperationException($"Unhandled outcome {result.Outcome}."),
    };

    public static IResult NotFound() => Problem(
        StatusCodes.Status404NotFound,
        "Not found.",
        "The resource does not exist or is not visible to the caller.");

    public static IResult Problem(int statusCode, string title, string? detail) =>
        Results.Problem(statusCode: statusCode, title: title, detail: detail);
}
