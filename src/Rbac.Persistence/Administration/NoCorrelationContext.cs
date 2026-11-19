using Rbac.Abstractions;

namespace Rbac.Persistence.Administration;

/// <summary>The default for hosts without an HTTP request: audit entries carry no correlation id.</summary>
internal sealed class NoCorrelationContext : ICorrelationContext
{
    public string? CorrelationId => null;
}
