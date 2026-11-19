using Rbac.Abstractions;
using Rbac.Core.Catalog;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Catalog;

public class RoleCatalogHolderTests
{
    [Fact]
    public void The_holder_serves_the_initial_catalog_until_it_is_replaced()
    {
        var holder = new RoleCatalogHolder(DefaultRoleCatalog.Create());
        holder.Find(RoleKeys.AgencyStaff)!.Family.ShouldBe(RoleFamily.Agency);

        holder.Replace(RoleCatalog.Create().Role(RoleKeys.AgencyStaff, RoleFamily.Internal).Build());

        holder.Find(RoleKeys.AgencyStaff)!.Family.ShouldBe(RoleFamily.Internal);
        holder.Roles.Count.ShouldBe(1);
        holder.Find(RoleKeys.SystemAdmin).ShouldBeNull();
    }
}
