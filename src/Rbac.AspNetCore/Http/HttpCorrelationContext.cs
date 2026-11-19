using Microsoft.AspNetCore.Http;
using Rbac.Abstractions;

namespace Rbac.AspNetCore.Http;

internal sealed class HttpCorrelationContext(IHttpContextAccessor accessor) : ICorrelationContext
{
    public string? CorrelationId => accessor.HttpContext?.GetCorrelationId();
}
