namespace Rbac.Core.Validation;

/// <summary>Thrown at startup when the role catalog and strategy registry are inconsistent.</summary>
public sealed class RbacConfigurationException(IReadOnlyList<string> problems)
    : InvalidOperationException(BuildMessage(problems))
{
    public IReadOnlyList<string> Problems { get; } = problems;

    private static string BuildMessage(IReadOnlyList<string> problems) =>
        "RBAC configuration is invalid: " + string.Join("; ", problems);
}
