namespace Rbac.Abstractions;

/// <summary>Resolves a caller's effective permissions live; permissions are never trusted from a token snapshot.</summary>
public interface IPermissionStore
{
    ValueTask<PermissionSet> GetEffectivePermissionsAsync(Principal principal, CancellationToken cancellationToken);
}
