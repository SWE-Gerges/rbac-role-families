using Microsoft.EntityFrameworkCore;
using Rbac.Core.Catalog;
using Rbac.Core.Users;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence.Seeding;

public static class DemoSeeder
{
    /// <summary>
    /// Writes the demo tenants, users, overrides and bookings once, and gives each new tenant its own copy of the catalog's role
    /// defaults. Does nothing when tenants already exist. A seeded user's handle is its id.
    /// </summary>
    public static async Task SeedAsync(RbacDbContext db, RoleCatalog catalog, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(catalog);

        if (await db.Tenants.AnyAsync(cancellationToken))
        {
            return;
        }

        foreach (var (id, name) in DemoSeedData.Tenants)
        {
            db.Tenants.Add(new TenantEntity { Id = id, Name = name });
        }

        foreach (var user in DemoSeedData.Users)
        {
            db.Users.Add(new User
            {
                Id = user.Id,
                Handle = user.Id,
                IsFoundingAdmin = user.IsFoundingAdmin,
                TenantId = user.TenantId,
                DisplayName = user.DisplayName,
                Kind = user.Kind,
                RoleKey = user.RoleKey,
                AgencyId = user.AgencyId,
                CorporateId = user.CorporateId,
                IsActive = true,
            });

            foreach (var grant in user.Grants)
            {
                db.UserPermissions.Add(new UserPermissionEntity
                {
                    TenantId = user.TenantId,
                    UserId = user.Id,
                    PermissionKey = grant,
                    Effect = PermissionEffect.Grant,
                });
            }
        }

        db.Bookings.AddRange(DemoSeedData.CreateBookings(catalog));
        await db.SaveChangesAsync(cancellationToken);

        foreach (var (id, _) in DemoSeedData.Tenants)
        {
            await PermissionSeeder.SeedTenantAsync(db, id, catalog, cancellationToken);
        }
    }
}
