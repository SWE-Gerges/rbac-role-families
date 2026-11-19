using Rbac.Abstractions;
using Rbac.Core.Registry;

namespace Rbac.Core.Validation;

/// <summary>
/// Checks the role catalog and strategy registries for the misconfigurations that would otherwise
/// surface as wrong data scoping at runtime.
/// </summary>
public static class RbacConfigurationValidator
{
    public static IReadOnlyList<string> Validate(IRoleCatalog catalog, IEnumerable<IStrategyRegistry> registries)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(registries);

        var problems = new List<string>();
        ValidateRoles(catalog, problems);
        ValidateRegistries(registries.ToArray(), problems);
        return problems;
    }

    private static void ValidateRoles(IRoleCatalog catalog, List<string> problems)
    {
        var roles = catalog.Roles;

        foreach (var role in roles)
        {
            if (string.IsNullOrWhiteSpace(role.Key))
            {
                problems.Add("A role has an empty key.");
                continue;
            }

            if (!Enum.IsDefined(role.Family))
            {
                problems.Add($"Role '{role.Key}' has no valid role family.");
            }
        }

        foreach (var duplicate in roles.Where(r => !string.IsNullOrWhiteSpace(r.Key))
                     .GroupBy(r => r.Key, StringComparer.Ordinal)
                     .Where(g => g.Count() > 1))
        {
            problems.Add($"Role key '{duplicate.Key}' is defined {duplicate.Count()} times.");
        }

        var knownKeys = roles.Select(r => r.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var role in roles)
        {
            foreach (var creatable in role.CreatableRoleKeys.Where(k => !knownKeys.Contains(k)))
            {
                problems.Add($"Role '{role.Key}' can create '{creatable}', which is not a defined role.");
            }
        }
    }

    private static void ValidateRegistries(IReadOnlyList<IStrategyRegistry> registries, List<string> problems)
    {
        if (registries.Count == 0)
        {
            problems.Add("No strategy registry is registered, so no family has a strategy.");
            return;
        }

        foreach (var registry in registries)
        {
            foreach (var family in Enum.GetValues<RoleFamily>())
            {
                var count = registry.RegisteredFamilies.Count(f => f == family);
                if (count == 0)
                {
                    problems.Add($"Family '{family}' has no strategy for {registry.ResourceName}.");
                }
                else if (count > 1)
                {
                    problems.Add($"Family '{family}' has {count} strategies for {registry.ResourceName}; exactly one is required.");
                }
            }

            foreach (var undefined in registry.RegisteredFamilies.Where(f => !Enum.IsDefined(f)).Distinct())
            {
                problems.Add($"A strategy for {registry.ResourceName} is registered for the undefined family '{(int)undefined}'.");
            }
        }
    }
}
