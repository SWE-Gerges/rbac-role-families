namespace Rbac.Abstractions;

/// <summary>The single source of truth for which staff roles exist.</summary>
public interface IRoleCatalog
{
    IReadOnlyList<RoleDefinition> Roles { get; }

    /// <summary>Returns the one role with this key, or null when it is unknown or ambiguous (fail closed).</summary>
    RoleDefinition? Find(string? roleKey);
}
