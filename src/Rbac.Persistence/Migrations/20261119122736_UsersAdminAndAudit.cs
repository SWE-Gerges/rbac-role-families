using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rbac.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class UsersAdminAndAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "User",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Handle",
                table: "User",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            // Existing users keep their id as their handle, so the unique index below can be built.
            migrationBuilder.Sql("UPDATE \"User\" SET \"Handle\" = \"Id\"");

            migrationBuilder.AddColumn<bool>(
                name: "IsFoundingAdmin",
                table: "User",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "PermissionsVersion",
                table: "User",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<bool>(
                name: "IsAdmin",
                table: "Role",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "AuditEntry",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    TenantId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ActorUserId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    EffectiveUserId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Action = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    TargetType = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    TargetId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Before = table.Column<string>(type: "text", nullable: true),
                    After = table.Column<string>(type: "text", nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    At = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEntry", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_User_FoundingAdmin_Agency",
                table: "User",
                columns: new[] { "TenantId", "AgencyId" },
                unique: true,
                filter: "\"IsFoundingAdmin\" IS TRUE AND \"DeletedAt\" IS NULL AND \"AgencyId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_User_FoundingAdmin_Corporate",
                table: "User",
                columns: new[] { "TenantId", "CorporateId" },
                unique: true,
                filter: "\"IsFoundingAdmin\" IS TRUE AND \"DeletedAt\" IS NULL AND \"CorporateId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_User_TenantId_Handle",
                table: "User",
                columns: new[] { "TenantId", "Handle" },
                unique: true,
                filter: "\"DeletedAt\" IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEntry_TenantId_ActorUserId",
                table: "AuditEntry",
                columns: new[] { "TenantId", "ActorUserId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEntry_TenantId_At",
                table: "AuditEntry",
                columns: new[] { "TenantId", "At" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEntry_TenantId_TargetId",
                table: "AuditEntry",
                columns: new[] { "TenantId", "TargetId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditEntry");

            migrationBuilder.DropIndex(
                name: "IX_User_FoundingAdmin_Agency",
                table: "User");

            migrationBuilder.DropIndex(
                name: "IX_User_FoundingAdmin_Corporate",
                table: "User");

            migrationBuilder.DropIndex(
                name: "IX_User_TenantId_Handle",
                table: "User");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "User");

            migrationBuilder.DropColumn(
                name: "Handle",
                table: "User");

            migrationBuilder.DropColumn(
                name: "IsFoundingAdmin",
                table: "User");

            migrationBuilder.DropColumn(
                name: "PermissionsVersion",
                table: "User");

            migrationBuilder.DropColumn(
                name: "IsAdmin",
                table: "Role");
        }
    }
}
