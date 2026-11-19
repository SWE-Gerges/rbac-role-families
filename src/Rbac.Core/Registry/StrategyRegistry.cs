using System.Collections.Frozen;
using Rbac.Abstractions;
using Rbac.Core.Scopes;

namespace Rbac.Core.Registry;

/// <summary>Non-generic view of a registry, used by startup validation.</summary>
public interface IStrategyRegistry
{
    string ResourceName { get; }

    /// <summary>Every family registration in registration order, including duplicates and undefined families.</summary>
    IReadOnlyList<RoleFamily> RegisteredFamilies { get; }
}

/// <summary>
/// An explicit map from role family to scope strategy. Selection is a lookup by family, never a scan
/// over a list of strategies, so it cannot depend on registration order.
/// </summary>
public sealed class StrategyRegistry<TResource> : IStrategyRegistry
{
    private readonly FrozenDictionary<RoleFamily, IAccessScopeStrategy<TResource>> _byFamily;

    internal StrategyRegistry(
        IReadOnlyList<(RoleFamily Family, IAccessScopeStrategy<TResource> Strategy)> registrations,
        IAccessScopeStrategy<TResource>? customer,
        IAccessScopeStrategy<TResource> fallback)
    {
        RegisteredFamilies = registrations.Select(r => r.Family).ToArray();
        _byFamily = registrations
            .GroupBy(r => r.Family)
            .Where(g => g.Count() == 1)
            .ToFrozenDictionary(g => g.Key, g => g.Single().Strategy);
        Customer = customer;
        Fallback = fallback;
    }

    public string ResourceName => typeof(TResource).Name;

    public IReadOnlyList<RoleFamily> RegisteredFamilies { get; }

    /// <summary>The strategy for customers, who are not members of any staff family.</summary>
    public IAccessScopeStrategy<TResource>? Customer { get; }

    /// <summary>Used whenever nothing more specific applies. Defaults to no access.</summary>
    public IAccessScopeStrategy<TResource> Fallback { get; }

    /// <summary>The strategy registered for the family, or the fallback when it is missing or registered more than once.</summary>
    public IAccessScopeStrategy<TResource> ForFamily(RoleFamily family) =>
        _byFamily.TryGetValue(family, out var strategy) ? strategy : Fallback;

    public static StrategyRegistryBuilder<TResource> Create() => new();
}

public sealed class StrategyRegistryBuilder<TResource>
{
    private readonly List<(RoleFamily, IAccessScopeStrategy<TResource>)> _registrations = [];
    private IAccessScopeStrategy<TResource>? _customer;
    private IAccessScopeStrategy<TResource> _fallback = new NoAccessScope<TResource>();

    public StrategyRegistryBuilder<TResource> ForFamily(RoleFamily family, IAccessScopeStrategy<TResource> strategy)
    {
        ArgumentNullException.ThrowIfNull(strategy);
        _registrations.Add((family, strategy));
        return this;
    }

    public StrategyRegistryBuilder<TResource> ForCustomers(IAccessScopeStrategy<TResource> strategy)
    {
        _customer = strategy ?? throw new ArgumentNullException(nameof(strategy));
        return this;
    }

    public StrategyRegistryBuilder<TResource> Fallback(IAccessScopeStrategy<TResource> strategy)
    {
        _fallback = strategy ?? throw new ArgumentNullException(nameof(strategy));
        return this;
    }

    public StrategyRegistry<TResource> Build() => new(_registrations, _customer, _fallback);
}
