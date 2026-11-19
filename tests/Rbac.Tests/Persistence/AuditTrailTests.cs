using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Rbac.Persistence;
using Rbac.Persistence.Administration;
using Rbac.Persistence.Entities;
using Rbac.Persistence.Seeding;
using Rbac.Tests.Support;
using Shouldly;
using Xunit;

namespace Rbac.Tests.Persistence;

/// <summary>The audit trail is append-only: no update or delete path in the model, an interceptor on the EF path and triggers for everything else.</summary>
public class AuditTrailTests
{
    private static AuditEntryEntity Entry(string id, string tenantId = SeedIds.TenantA) => new()
    {
        Id = id,
        TenantId = tenantId,
        ActorUserId = SeedIds.SystemAdminA,
        Action = "user.created",
        TargetType = "User",
        TargetId = "usr-1",
        After = "{\"handle\":\"x\"}",
        At = new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero),
    };

    private static async Task<(SqliteTestDatabase Database, RbacDbContext Db)> WithOneEntryAsync()
    {
        var database = await SqliteTestDatabase.CreateAsync();
        var db = database.CreateContext(SeedIds.TenantA);
        db.Add(Entry("aud-1"));
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        db.ChangeTracker.Clear();
        return (database, db);
    }

    [Fact]
    public void The_entity_has_no_setters_and_the_context_exposes_no_writable_set()
    {
        foreach (var property in typeof(AuditEntryEntity).GetProperties())
        {
            var setter = property.SetMethod;
            setter.ShouldNotBeNull(property.Name);
            setter.ReturnParameter.GetRequiredCustomModifiers().ShouldContain(typeof(IsExternalInit), $"{property.Name} must be init-only");
        }

        typeof(RbacDbContext).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(DbSet<AuditEntryEntity>))
            .ShouldBeEmpty("audit entries are added through IAuditLog, never through a DbSet");
        typeof(RbacDbContext).GetProperty(nameof(RbacDbContext.AuditEntries))!.PropertyType.ShouldBe(typeof(IQueryable<AuditEntryEntity>));
    }

    [Fact]
    public async Task New_entries_save_and_read_back_without_tracking()
    {
        var (database, db) = await WithOneEntryAsync();
        await using var _ = database;
        await using var __ = db;

        var stored = await db.AuditEntries.SingleAsync(TestContext.Current.CancellationToken);

        stored.Id.ShouldBe("aud-1");
        stored.After.ShouldBe("{\"handle\":\"x\"}");
        db.ChangeTracker.Entries().ShouldBeEmpty("the read side does not track");
    }

    [Fact]
    public async Task A_tracked_entry_marked_modified_makes_save_changes_throw_and_nothing_else_in_that_save_is_written()
    {
        var (database, db) = await WithOneEntryAsync();
        await using var _ = database;
        await using var __ = db;
        var tracked = await db.Set<AuditEntryEntity>().SingleAsync(TestContext.Current.CancellationToken);
        db.Entry(tracked).State = EntityState.Modified;
        db.Tenants.Add(new TenantEntity { Id = "tenant-c", Name = "Tenant C" });

        var exception = await Should.ThrowAsync<AuditTrailImmutableException>(() => db.SaveChangesAsync(TestContext.Current.CancellationToken));

        exception.Message.ShouldContain("append-only");
        db.ChangeTracker.Clear();
        (await db.Tenants.AnyAsync(t => t.Id == "tenant-c", TestContext.Current.CancellationToken)).ShouldBeFalse();
    }

    [Fact]
    public async Task A_tracked_entry_marked_deleted_makes_save_changes_throw_on_both_sync_and_async_paths()
    {
        var (database, db) = await WithOneEntryAsync();
        await using var _ = database;
        await using var __ = db;
        var tracked = await db.Set<AuditEntryEntity>().SingleAsync(TestContext.Current.CancellationToken);
        db.Remove(tracked);

        await Should.ThrowAsync<AuditTrailImmutableException>(() => db.SaveChangesAsync(TestContext.Current.CancellationToken));
        Should.Throw<AuditTrailImmutableException>(() => db.SaveChanges());

        db.ChangeTracker.Clear();
        (await db.AuditEntries.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task Raw_update_and_delete_are_rejected_by_the_trigger()
    {
        var (database, db) = await WithOneEntryAsync();
        await using var _ = database;
        await using var __ = db;

        var update = await Should.ThrowAsync<SqliteException>(() =>
            db.Database.ExecuteSqlRawAsync("UPDATE \"AuditEntry\" SET \"Action\" = 'tampered'", TestContext.Current.CancellationToken));
        var delete = await Should.ThrowAsync<SqliteException>(() =>
            db.Database.ExecuteSqlRawAsync("DELETE FROM \"AuditEntry\"", TestContext.Current.CancellationToken));

        update.Message.ShouldContain("append-only");
        delete.Message.ShouldContain("append-only");
        (await db.AuditEntries.SingleAsync(TestContext.Current.CancellationToken)).Action.ShouldBe("user.created");
    }

    [Fact]
    public async Task Set_based_ef_statements_bypass_the_interceptor_and_are_stopped_by_the_trigger()
    {
        var (database, db) = await WithOneEntryAsync();
        await using var _ = database;
        await using var __ = db;

        await Should.ThrowAsync<SqliteException>(() => db.Set<AuditEntryEntity>()
            .ExecuteUpdateAsync(s => s.SetProperty(e => e.Action, "tampered"), TestContext.Current.CancellationToken));
        await Should.ThrowAsync<SqliteException>(() => db.Set<AuditEntryEntity>().ExecuteDeleteAsync(TestContext.Current.CancellationToken));

        (await db.AuditEntries.SingleAsync(TestContext.Current.CancellationToken)).Action.ShouldBe("user.created");
    }

    [Fact]
    public async Task The_triggers_can_be_installed_twice_and_inserts_still_work()
    {
        var (database, db) = await WithOneEntryAsync();
        await using var _ = database;
        await using var __ = db;

        await SqliteSchema.CreateAsync(db, TestContext.Current.CancellationToken);
        db.Add(Entry("aud-2"));
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);

        (await db.AuditEntries.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(2);
    }

    [Fact]
    public async Task Entries_are_tenant_scoped_by_the_global_filter()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await using (var writer = database.CreateContext(SeedIds.TenantA))
        {
            writer.Add(Entry("aud-a"));
            writer.Add(Entry("aud-b", SeedIds.TenantB));
            await writer.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var tenantB = database.CreateContext(SeedIds.TenantB);
        await using var nobody = database.CreateContext(tenantId: null);

        (await tenantB.AuditEntries.Select(e => e.Id).ToListAsync(TestContext.Current.CancellationToken)).ShouldBe(["aud-b"]);
        (await nobody.AuditEntries.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(0);
    }
}
