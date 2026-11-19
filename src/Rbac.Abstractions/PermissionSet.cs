using System.Collections;
using System.Collections.Frozen;

namespace Rbac.Abstractions;

/// <summary>An immutable set of permission strings compared ordinally.</summary>
public sealed class PermissionSet : IReadOnlyCollection<string>
{
    private readonly FrozenSet<string> _permissions;

    private PermissionSet(FrozenSet<string> permissions) => _permissions = permissions;

    public static PermissionSet Empty { get; } = new(FrozenSet<string>.Empty);

    public int Count => _permissions.Count;

    public static PermissionSet Create(IEnumerable<string> permissions)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        var set = permissions.ToFrozenSet(StringComparer.Ordinal);
        return set.Count == 0 ? Empty : new PermissionSet(set);
    }

    public static PermissionSet Create(params string[] permissions) => Create((IEnumerable<string>)permissions);

    public bool Has(string permission) => permission is not null && _permissions.Contains(permission);

    public IEnumerator<string> GetEnumerator() => _permissions.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
