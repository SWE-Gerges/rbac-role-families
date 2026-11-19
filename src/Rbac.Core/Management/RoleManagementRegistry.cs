using System.Collections.Frozen;
using Rbac.Abstractions;
using Rbac.Core.Registry;

namespace Rbac.Core.Management;

/// <summary>An explicit map from role family to management strategy, validated at startup like the scope registries.</summary>
public sealed class RoleManagementRegistry : IStrategyRegistry
{
    private readonly FrozenDictionary<RoleFamily, IRoleManagementStrategy> _byFamily;

    private RoleManagementRegistry(IReadOnlyList<(RoleFamily Family, IRoleManagementStrategy Strategy)> registrations)
    {
        RegisteredFamilies = registrations.Select(r => r.Family).ToArray();
        _byFamily = registrations
            .GroupBy(r => r.Family)
            .Where(g => g.Count() == 1)
            .ToFrozenDictionary(g => g.Key, g => g.Single().Strategy);
    }

    public string ResourceName => "RoleManagement";

    public IReadOnlyList<RoleFamily> RegisteredFamilies { get; }

    public IRoleManagementStrategy Fallback { get; } = new DenyAllRoleManagement();

    public IRoleManagementStrategy ForFamily(RoleFamily family) => _byFamily.GetValueOrDefault(family) ?? Fallback;

    public static Builder Create() => new();

    public sealed class Builder
    {
        private readonly List<(RoleFamily, IRoleManagementStrategy)> _registrations = [];

        public Builder ForFamily(RoleFamily family, IRoleManagementStrategy strategy)
        {
            _registrations.Add((family, strategy ?? throw new ArgumentNullException(nameof(strategy))));
            return this;
        }

        public RoleManagementRegistry Build() => new(_registrations);
    }
}

/// <summary>Maps the caller to the management strategy of their family. Anything unresolvable may manage nobody.</summary>
public sealed class RoleManagementResolver(IRoleCatalog catalog, RoleManagementRegistry registry)
{
    public IRoleManagementStrategy StrategyFor(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Kind != PrincipalKind.Staff)
        {
            return registry.Fallback;
        }

        var role = catalog.Find(principal.RoleKey);
        return role is null ? registry.Fallback : registry.ForFamily(role.Family);
    }
}
