namespace Rbac.Abstractions;

/// <summary>The correlation id of the current request, recorded on audit entries.</summary>
public interface ICorrelationContext
{
    string? CorrelationId { get; }
}
