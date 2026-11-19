using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Rbac.Persistence;

/// <summary>Used only by the EF tooling to create migrations. The connection string is a placeholder.</summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<RbacDbContext>
{
    public RbacDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<RbacDbContext>()
            .UseNpgsql("Host=localhost;Database=rbac_design_time;Username=design;Password=design-only")
            .Options;
        return new RbacDbContext(options, FixedTenantContext.None);
    }
}
