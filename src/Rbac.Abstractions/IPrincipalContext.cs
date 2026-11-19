namespace Rbac.Abstractions;

/// <summary>The principal of the current request.</summary>
public interface IPrincipalContext
{
    Principal Current { get; }
}

/// <summary>The live permissions of the current request's principal, resolved at most once per request.</summary>
public interface ICurrentPermissions
{
    ValueTask<PermissionSet> GetAsync(CancellationToken cancellationToken);
}
