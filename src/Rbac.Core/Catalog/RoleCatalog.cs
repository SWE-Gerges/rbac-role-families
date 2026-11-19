using Rbac.Abstractions;

namespace Rbac.Core.Catalog;

/// <summary>
/// An immutable role catalog. It keeps duplicates so the startup validator can report them;
/// <see cref="Find"/> treats an ambiguous key as unknown.
/// </summary>
public sealed class RoleCatalog : IRoleCatalog
{
    private readonly ILookup<string, RoleDefinition> _byKey;

    private RoleCatalog(IReadOnlyList<RoleDefinition> roles, int version)
    {
        Roles = roles;
        Version = version;
        _byKey = roles.Where(r => r.Key is not null).ToLookup(r => r.Key, StringComparer.Ordinal);
    }

    public IReadOnlyList<RoleDefinition> Roles { get; }

    /// <summary>Bumped whenever the code-defined catalog changes, so storage knows when to sync structure and add new defaults.</summary>
    public int Version { get; }

    public static RoleCatalogBuilder Create() => new();

    public static RoleCatalog FromDefinitions(IEnumerable<RoleDefinition> roles, int version = 1)
    {
        ArgumentNullException.ThrowIfNull(roles);
        return new RoleCatalog(roles.ToArray(), version);
    }

    public RoleDefinition? Find(string? roleKey)
    {
        if (string.IsNullOrEmpty(roleKey))
        {
            return null;
        }

        using var matches = _byKey[roleKey].GetEnumerator();
        if (!matches.MoveNext())
        {
            return null;
        }

        var first = matches.Current;
        return matches.MoveNext() ? null : first;
    }
}

public sealed class RoleCatalogBuilder
{
    private readonly List<RoleDefinition> _roles = [];
    private int _version = 1;

    public RoleCatalogBuilder Version(int version)
    {
        _version = version;
        return this;
    }

    public RoleCatalogBuilder Role(string key, RoleFamily family, Action<RoleBuilder>? configure = null)
    {
        var builder = new RoleBuilder();
        configure?.Invoke(builder);
        _roles.Add(new RoleDefinition(key, family, builder.Permissions, builder.Creatable, builder.IsAdmin));
        return this;
    }

    public RoleCatalog Build() => RoleCatalog.FromDefinitions(_roles, _version);
}

public sealed class RoleBuilder
{
    private readonly HashSet<string> _permissions = new(StringComparer.Ordinal);
    private readonly List<string> _creatable = [];

    internal IReadOnlySet<string> Permissions => _permissions;

    internal IReadOnlyList<string> Creatable => _creatable;

    internal bool IsAdmin { get; private set; }

    public RoleBuilder Admin()
    {
        IsAdmin = true;
        return this;
    }

    public RoleBuilder Grants(params string[] permissions)
    {
        _permissions.UnionWith(permissions);
        return this;
    }

    public RoleBuilder CanCreate(params string[] roleKeys)
    {
        _creatable.AddRange(roleKeys);
        return this;
    }
}
