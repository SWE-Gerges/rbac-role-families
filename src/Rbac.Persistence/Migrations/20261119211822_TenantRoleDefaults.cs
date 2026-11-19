using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rbac.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TenantRoleDefaults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_RolePermission",
                table: "RolePermission");

            migrationBuilder.DropPrimaryKey(
                name: "PK_RoleDefaultSeed",
                table: "RoleDefaultSeed");

            migrationBuilder.AddColumn<string>(
                name: "TenantId",
                table: "RolePermission",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "TenantId",
                table: "RoleDefaultSeed",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            // Role defaults used to be global. Give every existing tenant its own copy of them, then drop the global rows (the ones
            // that still carry the empty placeholder tenant). The new primary key can only be added after this, because the same
            // role and permission now appear once per tenant. Not exercised by any test here: nothing in this repository runs
            // against a Postgres server.
            migrationBuilder.Sql(
                "INSERT INTO \"RolePermission\" (\"TenantId\", \"RoleKey\", \"PermissionKey\") " +
                "SELECT t.\"Id\", rp.\"RoleKey\", rp.\"PermissionKey\" FROM \"RolePermission\" rp CROSS JOIN \"Tenant\" t WHERE rp.\"TenantId\" = ''");
            migrationBuilder.Sql("DELETE FROM \"RolePermission\" WHERE \"TenantId\" = ''");
            migrationBuilder.Sql(
                "INSERT INTO \"RoleDefaultSeed\" (\"TenantId\", \"RoleKey\", \"PermissionKey\", \"SeededInVersion\") " +
                "SELECT t.\"Id\", s.\"RoleKey\", s.\"PermissionKey\", s.\"SeededInVersion\" FROM \"RoleDefaultSeed\" s CROSS JOIN \"Tenant\" t WHERE s.\"TenantId\" = ''");
            migrationBuilder.Sql("DELETE FROM \"RoleDefaultSeed\" WHERE \"TenantId\" = ''");

            migrationBuilder.AddPrimaryKey(
                name: "PK_RolePermission",
                table: "RolePermission",
                columns: new[] { "TenantId", "RoleKey", "PermissionKey" });

            migrationBuilder.AddPrimaryKey(
                name: "PK_RoleDefaultSeed",
                table: "RoleDefaultSeed",
                columns: new[] { "TenantId", "RoleKey", "PermissionKey" });

            migrationBuilder.CreateIndex(
                name: "IX_RolePermission_RoleKey",
                table: "RolePermission",
                column: "RoleKey");

            migrationBuilder.AddForeignKey(
                name: "FK_RolePermission_Tenant_TenantId",
                table: "RolePermission",
                column: "TenantId",
                principalTable: "Tenant",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_RolePermission_Tenant_TenantId",
                table: "RolePermission");

            migrationBuilder.DropPrimaryKey(
                name: "PK_RolePermission",
                table: "RolePermission");

            migrationBuilder.DropIndex(
                name: "IX_RolePermission_RoleKey",
                table: "RolePermission");

            migrationBuilder.DropPrimaryKey(
                name: "PK_RoleDefaultSeed",
                table: "RoleDefaultSeed");

            // Collapse the per-tenant copies back to one global row per role and permission before the old keys return.
            migrationBuilder.Sql(
                "DELETE FROM \"RolePermission\" a USING \"RolePermission\" b " +
                "WHERE a.\"RoleKey\" = b.\"RoleKey\" AND a.\"PermissionKey\" = b.\"PermissionKey\" AND a.\"TenantId\" > b.\"TenantId\"");
            migrationBuilder.Sql(
                "DELETE FROM \"RoleDefaultSeed\" a USING \"RoleDefaultSeed\" b " +
                "WHERE a.\"RoleKey\" = b.\"RoleKey\" AND a.\"PermissionKey\" = b.\"PermissionKey\" AND a.\"TenantId\" > b.\"TenantId\"");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "RolePermission");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "RoleDefaultSeed");

            migrationBuilder.AddPrimaryKey(
                name: "PK_RolePermission",
                table: "RolePermission",
                columns: new[] { "RoleKey", "PermissionKey" });

            migrationBuilder.AddPrimaryKey(
                name: "PK_RoleDefaultSeed",
                table: "RoleDefaultSeed",
                columns: new[] { "RoleKey", "PermissionKey" });
        }
    }
}
