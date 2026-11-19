using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rbac.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AuditAppendOnlyTrigger : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The audit trail is append-only in the database too: UPDATE, DELETE and TRUNCATE are rejected, including
            // set-based statements that never pass through EF's change tracker. This script is not exercised by any
            // test in this repository (nothing here runs against a Postgres server); the SQLite equivalent is.
            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_entry_reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'audit entries are append-only';
                END;
                $$;
                """);
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_entry_no_update BEFORE UPDATE ON "AuditEntry"
                FOR EACH ROW EXECUTE FUNCTION audit_entry_reject_change();
                """);
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_entry_no_delete BEFORE DELETE ON "AuditEntry"
                FOR EACH ROW EXECUTE FUNCTION audit_entry_reject_change();
                """);
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_entry_no_truncate BEFORE TRUNCATE ON "AuditEntry"
                FOR EACH STATEMENT EXECUTE FUNCTION audit_entry_reject_change();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""DROP TRIGGER audit_entry_no_truncate ON "AuditEntry";""");
            migrationBuilder.Sql("""DROP TRIGGER audit_entry_no_delete ON "AuditEntry";""");
            migrationBuilder.Sql("""DROP TRIGGER audit_entry_no_update ON "AuditEntry";""");
            migrationBuilder.Sql("DROP FUNCTION audit_entry_reject_change();");
        }
    }
}
