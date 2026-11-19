using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using Rbac.AspNetCore.Http;

namespace Rbac.Demo.OpenApi;

internal static class OpenApiConfiguration
{
    private const string BearerScheme = "Bearer";

    public static void Configure(OpenApiOptions options)
    {
        options.AddDocumentTransformer((document, _, _) =>
        {
            document.Info = new OpenApiInfo
            {
                Title = "RBAC role families demo API",
                Version = "v1",
                Description =
                    "A booking API whose data scope depends on the caller's role family. "
                    + "Every read goes through one scope rule, so lists and by-id lookups agree. "
                    + "Out-of-scope resources return 404; missing permissions return 403; missing or revoked tokens return 401.",
            };

            // The host name is a deployment detail, not part of the contract.
            document.Servers = null;

            document.Components ??= new OpenApiComponents();
            document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
            document.Components.SecuritySchemes[BearerScheme] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
            };
            return Task.CompletedTask;
        });

        options.AddOperationTransformer((operation, context, _) =>
        {
            var allowsAnonymous = context.Description.ActionDescriptor.EndpointMetadata.OfType<IAllowAnonymous>().Any();
            if (!allowsAnonymous)
            {
                operation.Security ??= [];
                operation.Security.Add(new OpenApiSecurityRequirement
                {
                    [new OpenApiSecuritySchemeReference(BearerScheme, context.Document)] = [],
                });

                operation.Parameters ??= [];
                operation.Parameters.Add(new OpenApiParameter
                {
                    Name = OnBehalfMiddleware.HeaderName,
                    In = ParameterLocation.Header,
                    Required = false,
                    Description =
                        "Act as another user. Needs users.act-on-behalf, a target the caller outranks inside their tenant (and account), "
                        + "and applies the target's scope and permissions. Refused with 403 or 404, never ignored.",
                    Schema = new OpenApiSchema { Type = JsonSchemaType.String },
                });
            }

            return Task.CompletedTask;
        });
    }
}
