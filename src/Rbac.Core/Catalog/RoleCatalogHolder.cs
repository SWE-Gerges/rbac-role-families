using Rbac.Abstractions;

namespace Rbac.Core.Catalog;

/// <summary>The role catalog the host was configured with in code. It seeds storage once; it is not what runs.</summary>
public sealed record RoleCatalogSeed(RoleCatalog Catalog);

/// <summary>
/// The catalog the application reads at runtime. It starts as the code-defined catalog and is replaced by the stored
/// catalog once the database has been prepared, so storage is the single source of truth after startup.
/// </summary>
public sealed class RoleCatalogHolder(IRoleCatalog initial) : IRoleCatalog
{
    private volatile IRoleCatalog _current = initial ?? throw new ArgumentNullException(nameof(initial));

    public IReadOnlyList<RoleDefinition> Roles => _current.Roles;

    public RoleDefinition? Find(string? roleKey) => _current.Find(roleKey);

    public void Replace(IRoleCatalog catalog) => _current = catalog ?? throw new ArgumentNullException(nameof(catalog));
}
