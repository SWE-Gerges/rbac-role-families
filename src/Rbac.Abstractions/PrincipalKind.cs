namespace Rbac.Abstractions;

/// <summary>
/// Customers and anonymous callers are not members of any staff role family.
/// The default value is <see cref="Anonymous"/> so an uninitialised principal fails closed.
/// </summary>
public enum PrincipalKind
{
    Anonymous = 0,
    Staff = 1,
    Customer = 2,
}
