using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Rbac.AspNetCore;
using Rbac.AspNetCore.Claims;
using Rbac.AspNetCore.Http;
using Rbac.Core.Catalog;
using Rbac.Core.DependencyInjection;
using Rbac.Demo;
using Rbac.Demo.Endpoints;
using Rbac.Demo.Health;
using Rbac.Demo.OpenApi;
using Rbac.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddSimpleConsole(options => options.IncludeScopes = true);

builder.Services.AddOptions<DemoOptions>().BindConfiguration(DemoOptions.SectionName).ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<DemoOptions>, DemoOptionsValidator>();
builder.Services.AddOptions<PersistenceOptions>().BindConfiguration(PersistenceOptions.SectionName);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<DevTokenIssuer>();

// Order matters for hosted services: RBAC configuration is validated before the database is touched.
builder.Services.AddRbacCore(DefaultRoleCatalog.Create());
builder.Services.AddBookingScopes();
builder.Services.AddUserScopes();
builder.Services.AddRoleManagement();
builder.Services.AddRbacPersistence();
builder.Services.AddRbacAspNetCore();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.RemoveDataProtectionKeyRingWarmUp();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<DemoOptions>>((bearer, demo) =>
    {
        var jwt = demo.Value.Jwt;
        bearer.MapInboundClaims = false;
        bearer.Events = new RbacJwtBearerEvents();
        bearer.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = RbacClaimTypes.Subject,
            RoleClaimType = RbacClaimTypes.Role,
        };
    });

builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi(OpenApiConfiguration.Configure);
builder.Services.AddHealthChecks().AddDbContextCheck<RbacDbContext>("database", tags: ["ready"]);

var app = builder.Build();

app.UseCorrelationId();
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseAuthentication();
app.UseOnBehalf();
app.UseAuthorization();

app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false,
    ResponseWriter = HealthResponseWriter.WriteAsync,
}).AllowAnonymous();

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = HealthResponseWriter.WriteAsync,
}).AllowAnonymous();

app.MapOpenApi();
app.MapMeEndpoints();
app.MapBookingEndpoints();
app.MapAccessMatrixEndpoints();
app.MapUserEndpoints();
app.MapPermissionEndpoints();
app.MapAuditEndpoints();

if (app.Services.GetRequiredService<IOptions<DemoOptions>>().Value.EnableDevTokens)
{
    app.MapDevTokenEndpoints();
}

app.Run();

/// <summary>Entry point marker so integration tests can host the API.</summary>
public partial class Program;
