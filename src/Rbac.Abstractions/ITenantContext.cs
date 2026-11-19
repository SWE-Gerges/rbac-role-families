namespace Rbac.Abstractions;

/// <summary>The tenant of the current caller. Null means "no tenant", which matches no rows.</summary>
public interface ITenantContext
{
    string? TenantId { get; }
}
