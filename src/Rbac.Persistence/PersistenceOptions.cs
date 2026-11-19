namespace Rbac.Persistence;

public enum DatabaseProvider
{
    Sqlite,
    Postgres,
}

public sealed class PersistenceOptions
{
    public const string SectionName = "Persistence";

    /// <summary>SQLite runs the demo and every test; Postgres is the provider for real deployments (its migrations are committed, but no test here runs against a server).</summary>
    public DatabaseProvider Provider { get; set; } = DatabaseProvider.Sqlite;

    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>Create the schema (SQLite) or apply migrations (Postgres) and store the role catalog when the host starts.</summary>
    public bool InitializeOnStartup { get; set; } = true;

    /// <summary>
    /// Cache resolved permissions in process, validated on every request against the tenant's persisted epoch (one
    /// single-row read). Turn it off to resolve permissions from the database on every request.
    /// </summary>
    public bool CachePermissions { get; set; } = true;

    /// <summary>Also write the deterministic demo tenants, users and bookings.</summary>
    public bool SeedDemoData { get; set; }
}
