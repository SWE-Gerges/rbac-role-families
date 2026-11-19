using Rbac.Abstractions;

namespace Rbac.Core.Users;

/// <summary>
/// A person who can sign in. <see cref="Handle"/> is the identifier people know (unique among live users of a tenant);
/// <see cref="Id"/> never repeats, so a re-created account inherits nothing from a deleted one.
/// </summary>
public sealed class User
{
    public string Id { get; set; } = string.Empty;

    public string TenantId { get; set; } = string.Empty;

    public string Handle { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Staff or Customer. Customers have no role.</summary>
    public PrincipalKind Kind { get; set; }

    public string? RoleKey { get; set; }

    public string? AgencyId { get; set; }

    public string? CorporateId { get; set; }

    /// <summary>The first admin of an agency or corporate account. Each account has at most one.</summary>
    public bool IsFoundingAdmin { get; set; }

    public bool IsActive { get; set; } = true;

    /// <summary>Set when the user is soft deleted. Such users are invisible to every query and cannot sign in.</summary>
    public DateTimeOffset? DeletedAt { get; set; }

    /// <summary>Incremented by every permission change for this user. Clients send it back as <c>If-Match</c>.</summary>
    public int PermissionsVersion { get; set; } = 1;
}
