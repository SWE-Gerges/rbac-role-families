namespace Rbac.Abstractions;

/// <summary>
/// A staff role: its key, the family that selects its scope strategy, what it may do by default, the roles it may create,
/// and whether it is an admin tier role (as opposed to a staff tier role) within its account.
/// </summary>
public sealed record RoleDefinition(
    string Key,
    RoleFamily Family,
    IReadOnlySet<string> DefaultPermissions,
    IReadOnlyList<string> CreatableRoleKeys,
    bool IsAdmin = false);
