using Rbac.Abstractions;

namespace Rbac.Persistence;

/// <summary>A tenant context with a fixed value, for seeding, design time and tests.</summary>
public sealed class FixedTenantContext(string? tenantId) : ITenantContext
{
    /// <summary>No tenant: the global query filter matches nothing.</summary>
    public static FixedTenantContext None { get; } = new(null);

    public string? TenantId { get; } = tenantId;
}
