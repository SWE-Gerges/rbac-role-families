using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rbac.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class RoleDefaultSeeds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CatalogVersion",
                columns: table => new
                {
                    Name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CatalogVersion", x => x.Name);
                });

            migrationBuilder.CreateTable(
                name: "RoleDefaultSeed",
                columns: table => new
                {
                    RoleKey = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PermissionKey = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SeededInVersion = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RoleDefaultSeed", x => new { x.RoleKey, x.PermissionKey });
                });

            // Databases created before seeding was tracked already hold their role defaults. Record them as seeded so the
            // seeder never hands them out a second time (which would undo an administrator removing one).
            migrationBuilder.Sql(
                "INSERT INTO \"RoleDefaultSeed\" (\"RoleKey\", \"PermissionKey\", \"SeededInVersion\") " +
                "SELECT \"RoleKey\", \"PermissionKey\", 1 FROM \"RolePermission\"");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CatalogVersion");

            migrationBuilder.DropTable(
                name: "RoleDefaultSeed");
        }
    }
}
