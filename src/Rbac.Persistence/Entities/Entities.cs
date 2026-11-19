using Rbac.Abstractions;

namespace Rbac.Persistence.Entities;

public sealed class TenantEntity
{
    public string Id { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;
}

public sealed class RoleEntity
{
    public string Key { get; set; } = string.Empty;

    public RoleFamily Family { get; set; }

    public List<string> CreatableRoleKeys { get; set; } = [];

    /// <summary>Position in the code-defined catalog, so roles keep a stable, meaningful order.</summary>
    public int SortOrder { get; set; }

    public bool IsAdmin { get; set; }
}

public sealed class PermissionEntity
{
    public string Key { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// A default permission of a role <b>in one tenant</b>. Role definitions (key, family, creation graph) are global and immutable at
/// runtime; what a role grants by default belongs to the tenant, so an administrator edits only their own tenant's defaults.
/// </summary>
public sealed class RolePermissionEntity
{
    public string TenantId { get; set; } = string.Empty;

    public string RoleKey { get; set; } = string.Empty;

    public string PermissionKey { get; set; } = string.Empty;
}

public enum PermissionEffect
{
    Grant,
    Revoke,
}

/// <summary>A per-user override that sits on top of the role defaults.</summary>
public sealed class UserPermissionEntity
{
    public string TenantId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string PermissionKey { get; set; } = string.Empty;

    public PermissionEffect Effect { get; set; }
}

/// <summary>The current token version of a user. A user without a row is on version 1.</summary>
public sealed class TokenVersionEntity
{
    public string TenantId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public int Version { get; set; }
}

/// <summary>
/// Records that the seeder has handed a permission to a role as a default <b>in one tenant</b>, and in which catalog version. A
/// pair that is recorded here is never added again for that tenant, even when its administrator has since removed it from the role.
/// </summary>
public sealed class RoleDefaultSeedEntity
{
    public string TenantId { get; set; } = string.Empty;

    public string RoleKey { get; set; } = string.Empty;

    public string PermissionKey { get; set; } = string.Empty;

    public int SeededInVersion { get; set; }
}

/// <summary>The version of the code-defined role catalog that was last applied to this database.</summary>
public sealed class CatalogVersionEntity
{
    public const string RoleCatalogName = "role-catalog";

    public string Name { get; set; } = string.Empty;

    public int Version { get; set; }
}

/// <summary>The persisted permission epoch of a tenant. A tenant without a row is on epoch 0.</summary>
public sealed class PermissionEpochEntity
{
    public string TenantId { get; set; } = string.Empty;

    public long Epoch { get; set; }
}

/// <summary>
/// One row of the append-only audit trail, written in the same transaction as the change it describes.
/// Properties are init-only on purpose: there is no code path that edits an entry.
/// </summary>
public sealed class AuditEntryEntity
{
    public string Id { get; init; } = string.Empty;

    public string TenantId { get; init; } = string.Empty;

    /// <summary>The authenticated user who made the request.</summary>
    public string ActorUserId { get; init; } = string.Empty;

    /// <summary>The user whose scope applied, set only when the actor acted on behalf of someone else.</summary>
    public string? EffectiveUserId { get; init; }

    public string Action { get; init; } = string.Empty;

    public string TargetType { get; init; } = string.Empty;

    public string TargetId { get; init; } = string.Empty;

    public string? Before { get; init; }

    public string? After { get; init; }

    public string? CorrelationId { get; init; }

    public DateTimeOffset At { get; init; }
}
