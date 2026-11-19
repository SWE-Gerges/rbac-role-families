namespace Rbac.Abstractions;

/// <summary>
/// The unit of strategy selection. Every staff role belongs to exactly one family.
/// There is deliberately no zero member: an unset family is not a valid family.
/// </summary>
public enum RoleFamily
{
    System = 1,
    Finance = 2,
    Internal = 3,
    Corporate = 4,
    Agency = 5,
    Viewer = 6,
}
