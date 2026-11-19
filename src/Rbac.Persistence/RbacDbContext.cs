using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Rbac.Abstractions;
using Rbac.Core.Bookings;
using Rbac.Core.Users;
using Rbac.Persistence.Administration;
using Rbac.Persistence.Entities;

namespace Rbac.Persistence;

/// <summary>
/// Normalized RBAC tables plus bookings. Tenant-owned tables carry a global query filter driven by the
/// current principal's tenant; with no tenant the filter matches nothing.
/// </summary>
public sealed class RbacDbContext(DbContextOptions<RbacDbContext> options, ITenantContext tenantContext)
    : DbContext(options)
{
    public DbSet<TenantEntity> Tenants => Set<TenantEntity>();

    public DbSet<User> Users => Set<User>();

    public DbSet<RoleEntity> Roles => Set<RoleEntity>();

    public DbSet<PermissionEntity> Permissions => Set<PermissionEntity>();

    public DbSet<RolePermissionEntity> RolePermissions => Set<RolePermissionEntity>();

    public DbSet<UserPermissionEntity> UserPermissions => Set<UserPermissionEntity>();

    public DbSet<Booking> Bookings => Set<Booking>();

    public DbSet<TokenVersionEntity> TokenVersions => Set<TokenVersionEntity>();

    public DbSet<PermissionEpochEntity> PermissionEpochs => Set<PermissionEpochEntity>();

    public DbSet<RoleDefaultSeedEntity> RoleDefaultSeeds => Set<RoleDefaultSeedEntity>();

    public DbSet<CatalogVersionEntity> CatalogVersions => Set<CatalogVersionEntity>();

    /// <summary>The audit trail, read only. Entries are added through <see cref="AuditLog"/> and can never be changed or removed.</summary>
    public IQueryable<AuditEntryEntity> AuditEntries => Set<AuditEntryEntity>().AsNoTracking();

    // Stateless, so one shared instance keeps EF's internal service provider cache from growing per context.
    private static readonly AuditAppendOnlyInterceptor AppendOnly = new();

    // Read by the query filters. EF evaluates it per context instance and sends it as a parameter.
    private string? CurrentTenantId => tenantContext.TenantId;

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);

        // Registered here rather than by the host, so no way of constructing a context can skip it.
        optionsBuilder.AddInterceptors(AppendOnly);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<TenantEntity>(e =>
        {
            e.ToTable("Tenant");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(64);
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
        });

        modelBuilder.Entity<RoleEntity>(e =>
        {
            e.ToTable("Role");
            e.HasKey(x => x.Key);
            e.Property(x => x.Key).HasMaxLength(64);
            // An unknown stored family loads as the unset family so startup validation can report it instead of EF throwing.
            e.Property(x => x.Family)
                .HasConversion(v => v.ToString(), v => ParseFamily(v))
                .HasMaxLength(32)
                .IsRequired();
            e.Property(x => x.CreatableRoleKeys)
                .HasConversion(
                    v => string.Join(',', v),
                    v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(),
                    new ValueComparer<List<string>>(
                        (a, b) => a!.SequenceEqual(b!),
                        v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode(StringComparison.Ordinal))),
                        v => v.ToList()))
                .HasMaxLength(1024);
        });

        modelBuilder.Entity<PermissionEntity>(e =>
        {
            e.ToTable("Permission");
            e.HasKey(x => x.Key);
            e.Property(x => x.Key).HasMaxLength(64);
            e.Property(x => x.Description).HasMaxLength(400).IsRequired();
        });

        modelBuilder.Entity<RolePermissionEntity>(e =>
        {
            e.ToTable("RolePermission");
            e.HasKey(x => new { x.TenantId, x.RoleKey, x.PermissionKey });
            e.Property(x => x.TenantId).HasMaxLength(64);
            e.Property(x => x.RoleKey).HasMaxLength(64);
            e.Property(x => x.PermissionKey).HasMaxLength(64);
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<RoleEntity>().WithMany().HasForeignKey(x => x.RoleKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<PermissionEntity>().WithMany().HasForeignKey(x => x.PermissionKey).OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.TenantId == CurrentTenantId);
        });

        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("User");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(64);
            e.Property(x => x.TenantId).HasMaxLength(64).IsRequired();
            e.Property(x => x.Handle).HasMaxLength(64).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(200).IsRequired();
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(16).IsRequired();
            e.Property(x => x.RoleKey).HasMaxLength(64);
            e.Property(x => x.AgencyId).HasMaxLength(64);
            e.Property(x => x.CorporateId).HasMaxLength(64);
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<RoleEntity>().WithMany().HasForeignKey(x => x.RoleKey).OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(x => x.TenantId);
            // A handle can be used again once the user that held it is deleted; a founding admin is unique per live account.
            e.HasIndex(x => new { x.TenantId, x.Handle }).IsUnique().HasFilter("\"DeletedAt\" IS NULL");
            e.HasIndex(x => new { x.TenantId, x.AgencyId }).IsUnique().HasDatabaseName("IX_User_FoundingAdmin_Agency")
                .HasFilter("\"IsFoundingAdmin\" IS TRUE AND \"DeletedAt\" IS NULL AND \"AgencyId\" IS NOT NULL");
            e.HasIndex(x => new { x.TenantId, x.CorporateId }).IsUnique().HasDatabaseName("IX_User_FoundingAdmin_Corporate")
                .HasFilter("\"IsFoundingAdmin\" IS TRUE AND \"DeletedAt\" IS NULL AND \"CorporateId\" IS NOT NULL");
            e.HasQueryFilter(x => x.TenantId == CurrentTenantId && x.DeletedAt == null);
        });

        modelBuilder.Entity<UserPermissionEntity>(e =>
        {
            e.ToTable("UserPermission");
            e.HasKey(x => new { x.UserId, x.PermissionKey });
            e.Property(x => x.TenantId).HasMaxLength(64).IsRequired();
            e.Property(x => x.UserId).HasMaxLength(64);
            e.Property(x => x.PermissionKey).HasMaxLength(64);
            e.Property(x => x.Effect).HasConversion<string>().HasMaxLength(16).IsRequired();
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<PermissionEntity>().WithMany().HasForeignKey(x => x.PermissionKey).OnDelete(DeleteBehavior.Cascade);
            e.HasQueryFilter(x => x.TenantId == CurrentTenantId);
        });

        modelBuilder.Entity<TokenVersionEntity>(e =>
        {
            e.ToTable("TokenVersion");
            e.HasKey(x => new { x.TenantId, x.UserId });
            e.Property(x => x.TenantId).HasMaxLength(64);
            e.Property(x => x.UserId).HasMaxLength(64);
        });

        modelBuilder.Entity<RoleDefaultSeedEntity>(e =>
        {
            e.ToTable("RoleDefaultSeed");
            e.HasKey(x => new { x.TenantId, x.RoleKey, x.PermissionKey });
            e.Property(x => x.TenantId).HasMaxLength(64);
            e.Property(x => x.RoleKey).HasMaxLength(64);
            e.Property(x => x.PermissionKey).HasMaxLength(64);
        });

        modelBuilder.Entity<CatalogVersionEntity>(e =>
        {
            e.ToTable("CatalogVersion");
            e.HasKey(x => x.Name);
            e.Property(x => x.Name).HasMaxLength(64);
        });

        modelBuilder.Entity<PermissionEpochEntity>(e =>
        {
            e.ToTable("PermissionEpoch");
            e.HasKey(x => x.TenantId);
            e.Property(x => x.TenantId).HasMaxLength(64);
        });

        modelBuilder.Entity<AuditEntryEntity>(e =>
        {
            e.ToTable("AuditEntry");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(64);
            e.Property(x => x.TenantId).HasMaxLength(64).IsRequired();
            e.Property(x => x.ActorUserId).HasMaxLength(64).IsRequired();
            e.Property(x => x.EffectiveUserId).HasMaxLength(64);
            e.Property(x => x.Action).HasMaxLength(64).IsRequired();
            e.Property(x => x.TargetType).HasMaxLength(32).IsRequired();
            e.Property(x => x.TargetId).HasMaxLength(64).IsRequired();
            e.Property(x => x.CorrelationId).HasMaxLength(64);
            e.HasIndex(x => new { x.TenantId, x.At });
            e.HasIndex(x => new { x.TenantId, x.TargetId });
            e.HasIndex(x => new { x.TenantId, x.ActorUserId });
            e.HasQueryFilter(x => x.TenantId == CurrentTenantId);
        });

        modelBuilder.Entity<Booking>(ConfigureBooking);

        if (Database.IsSqlite())
        {
            ApplySqliteValueConversions(modelBuilder);
        }
    }

    private static RoleFamily ParseFamily(string value) =>
        Enum.TryParse<RoleFamily>(value, out var family) && Enum.IsDefined(family) ? family : default;

    private void ConfigureBooking(EntityTypeBuilder<Booking> e)
    {
        e.ToTable("Booking");
        e.HasKey(x => x.Id);
        e.Property(x => x.Id).HasMaxLength(64);
        e.Property(x => x.TenantId).HasMaxLength(64).IsRequired();
        e.Property(x => x.OwnerUserId).HasMaxLength(64).IsRequired();
        e.Property(x => x.OwnerRoleFamilyAtCreation).HasConversion<string>().HasMaxLength(32);
        e.Property(x => x.AgencyId).HasMaxLength(64);
        e.Property(x => x.CorporateId).HasMaxLength(64);
        e.Property(x => x.Type).HasConversion<string>().HasMaxLength(16).IsRequired();
        e.Property(x => x.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
        e.Property(x => x.Amount).HasPrecision(18, 2);
        e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Restrict);
        e.HasIndex(x => new { x.TenantId, x.Status });
        e.HasIndex(x => new { x.TenantId, x.AgencyId });
        e.HasIndex(x => new { x.TenantId, x.CorporateId });
        e.HasIndex(x => new { x.TenantId, x.OwnerUserId });
        e.HasIndex(x => new { x.TenantId, x.CreatedAt });
        e.HasQueryFilter(x => x.TenantId == CurrentTenantId);
    }

    // SQLite cannot order by DateTimeOffset, so it stores UTC ticks. The Npgsql model keeps timestamptz.
    private static void ApplySqliteValueConversions(ModelBuilder modelBuilder)
    {
        var converter = new ValueConverter<DateTimeOffset, long>(
            v => v.UtcTicks,
            v => new DateTimeOffset(v, TimeSpan.Zero));

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties().Where(p => p.ClrType == typeof(DateTimeOffset)))
            {
                property.SetValueConverter(converter);
            }
        }
    }
}
