using Rbac.Abstractions;

namespace Rbac.Core.Registry;

/// <summary>
/// Detects the caller's kind and role, maps the role to its family and looks the family up in the registry.
/// Anything that cannot be resolved (anonymous, unknown role, unregistered family) gets the fallback strategy.
/// </summary>
public sealed class ScopeResolver<TResource>(IRoleCatalog catalog, StrategyRegistry<TResource> registry)
    : IScopeResolver<TResource>
{
    public IAccessScopeStrategy<TResource> StrategyFor(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        switch (principal.Kind)
        {
            case PrincipalKind.Customer:
                return registry.Customer ?? registry.Fallback;
            case PrincipalKind.Staff:
                var role = catalog.Find(principal.RoleKey);
                return role is null ? registry.Fallback : registry.ForFamily(role.Family);
            default:
                return registry.Fallback;
        }
    }
}
