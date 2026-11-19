namespace Rbac.Persistence.Administration;

public enum AdminOutcome
{
    Ok,
    Created,
    NoContent,
    Invalid,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    PreconditionRequired,
}

/// <summary>The result of an administrative operation, mapped to an HTTP status by the caller.</summary>
public sealed record AdminResult<T>(
    AdminOutcome Outcome,
    T? Value = default,
    string? Message = null,
    IReadOnlyDictionary<string, string[]>? Errors = null)
{
    public bool Succeeded => Outcome is AdminOutcome.Ok or AdminOutcome.Created or AdminOutcome.NoContent;

    public static AdminResult<T> Ok(T value) => new(AdminOutcome.Ok, value);

    public static AdminResult<T> Created(T value) => new(AdminOutcome.Created, value);

    public static AdminResult<T> NoContent() => new(AdminOutcome.NoContent);

    public static AdminResult<T> NotFound() => new(AdminOutcome.NotFound);

    public static AdminResult<T> Forbidden(string message) => new(AdminOutcome.Forbidden, Message: message);

    public static AdminResult<T> Conflict(string message) => new(AdminOutcome.Conflict, Message: message);

    public static AdminResult<T> Invalid(string field, string message) =>
        new(AdminOutcome.Invalid, Errors: new Dictionary<string, string[]> { [field] = [message] });
}
