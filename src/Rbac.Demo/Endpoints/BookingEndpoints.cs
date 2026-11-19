using System.Linq.Expressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rbac.Abstractions;
using Rbac.AspNetCore.Authorization;
using Rbac.Core.Bookings;
using Rbac.Core.Catalog;
using Rbac.Demo.AccessMatrix;
using Rbac.Demo.Contracts;
using Rbac.Persistence;

namespace Rbac.Demo.Endpoints;

internal static class BookingEndpoints
{
    private const int DefaultPageSize = 20;
    private const int MaxPageSize = 100;
    private const decimal MaxAmount = 1_000_000m;

    public static IEndpointRouteBuilder MapBookingEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/bookings").WithTags("Bookings").WithMetadata(new ScopedResourceMetadata(ScopedResourceMetadata.Booking));

        group.MapGet("/", ListAsync)
            .WithName("ListBookings")
            .WithSummary("Lists the bookings the caller may see.")
            .WithDescription(
                "The same scope rule that powers by-id lookups. The X-Client-Channel header is a presentation hint and never changes the result.")
            .Produces<BookingListResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapGet("/{id}", GetAsync)
            .WithName("GetBooking")
            .WithSummary("Gets one booking. A booking outside the caller's scope is indistinguishable from a missing one (404).")
            .Produces<BookingResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/", CreateAsync)
            .WithName("CreateBooking")
            .WithSummary("Creates a draft booking. Ownership is stamped from the caller at write time.")
            .Produces<BookingResponse>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapPost("/{id}/cancel", CancelAsync)
            .WithName("CancelBooking")
            .WithSummary("Cancels a draft or confirmed booking that is inside the caller's scope.")
            .Produces<BookingResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        return app;
    }

    [RequirePermission(Permissions.BookingsRead)]
    private static async Task<IResult> ListAsync(
        IPrincipalContext principalContext,
        ICurrentPermissions permissions,
        IScopedQuery<Booking> bookings,
        [FromQuery] string? status,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromQuery] bool? mine,
        [FromHeader(Name = ChannelHint.HeaderName)] string? clientChannel,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();

        BookingStatus? statusFilter = null;
        if (!string.IsNullOrWhiteSpace(status))
        {
            if (Enum.TryParse<BookingStatus>(status, ignoreCase: true, out var parsed) && Enum.IsDefined(parsed) && !int.TryParse(status, out _))
            {
                statusFilter = parsed;
            }
            else
            {
                errors[nameof(status)] = [$"'{status}' is not a booking status. Use one of: {string.Join(", ", Enum.GetNames<BookingStatus>())}."];
            }
        }

        var pageNumber = page ?? 1;
        if (pageNumber < 1)
        {
            errors[nameof(page)] = ["page must be 1 or greater."];
        }

        var size = pageSize ?? DefaultPageSize;
        if (size is < 1 or > MaxPageSize)
        {
            errors[nameof(pageSize)] = [$"pageSize must be between 1 and {MaxPageSize}."];
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        var principal = principalContext.Current;
        var granted = await permissions.GetAsync(cancellationToken);

        Expression<Func<Booking, bool>>? narrowing = null;
        if (mine == true)
        {
            var userId = principal.UserId;
            narrowing = b => b.OwnerUserId == userId;
        }

        var query = bookings.ScopedFor(principal, granted, narrowing);
        if (statusFilter is { } wanted)
        {
            query = query.Where(b => b.Status == wanted);
        }

        var total = await query.CountAsync(cancellationToken);
        var items = await query
            .AsNoTracking()
            .OrderByDescending(b => b.CreatedAt)
            .ThenBy(b => b.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .ToListAsync(cancellationToken);

        return Results.Ok(new BookingListResponse(
            [.. items.Select(ToResponse)],
            pageNumber,
            size,
            total,
            ChannelHint.Parse(clientChannel)));
    }

    [RequirePermission(Permissions.BookingsRead)]
    private static async Task<IResult> GetAsync(
        string id,
        IPrincipalContext principalContext,
        ICurrentPermissions permissions,
        IScopedQuery<Booking> bookings,
        CancellationToken cancellationToken)
    {
        var granted = await permissions.GetAsync(cancellationToken);
        var booking = await bookings
            .ScopedFor(principalContext.Current, granted)
            .AsNoTracking()
            .Where(b => b.Id == id)
            .SingleOrDefaultAsync(cancellationToken);

        return booking is null ? NotFound() : Results.Ok(ToResponse(booking));
    }

    [RequirePermission(Permissions.BookingsCreate)]
    private static async Task<IResult> CreateAsync(
        CreateBookingRequest request,
        IPrincipalContext principalContext,
        OwnershipStamper stamper,
        RbacDbContext db,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (!Enum.IsDefined(request.Type))
        {
            errors[nameof(request.Type)] = [$"Type must be one of: {string.Join(", ", Enum.GetNames<BookingType>())}."];
        }

        if (request.Amount <= 0 || request.Amount > MaxAmount || decimal.Round(request.Amount, 2) != request.Amount)
        {
            errors[nameof(request.Amount)] = [$"Amount must be greater than 0 and at most {MaxAmount:0}, with at most two decimals."];
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        var stamp = stamper.Stamp(principalContext.Current);
        if (!stamp.Succeeded)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "The caller cannot own bookings.",
                detail: stamp.Failure switch
                {
                    StampFailure.MissingAgency => "The caller is not bound to an agency.",
                    StampFailure.MissingCorporate => "The caller is not bound to a corporate account.",
                    _ => "The caller's role is not recognised.",
                });
        }

        var booking = Booking.Create(
            $"bk-{Guid.CreateVersion7():N}",
            stamp.Stamp!,
            isGuestBooking: false,
            request.Type,
            BookingStatus.Draft,
            request.Amount,
            clock.GetUtcNow());

        db.Bookings.Add(booking);
        await db.SaveChangesAsync(cancellationToken);

        return Results.Created($"/api/v1/bookings/{booking.Id}", ToResponse(booking));
    }

    [RequirePermission(Permissions.BookingsCancel)]
    private static async Task<IResult> CancelAsync(
        string id,
        IPrincipalContext principalContext,
        ICurrentPermissions permissions,
        IScopedQuery<Booking> bookings,
        RbacDbContext db,
        CancellationToken cancellationToken)
    {
        var granted = await permissions.GetAsync(cancellationToken);
        var booking = await bookings
            .ScopedFor(principalContext.Current, granted)
            .Where(b => b.Id == id)
            .SingleOrDefaultAsync(cancellationToken);

        if (booking is null)
        {
            return NotFound();
        }

        if (booking.Cancel() == CancelOutcome.NotCancellable)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "The booking cannot be cancelled.",
                detail: $"A booking in status {booking.Status} cannot be cancelled.");
        }

        await db.SaveChangesAsync(cancellationToken);
        return Results.Ok(ToResponse(booking));
    }

    // One answer for "does not exist" and "not yours", so ids cannot be probed.
    private static IResult NotFound() => Results.Problem(
        statusCode: StatusCodes.Status404NotFound,
        title: "Booking not found.",
        detail: "The booking does not exist or is not visible to the caller.");

    private static BookingResponse ToResponse(Booking b) => new(
        b.Id,
        b.TenantId,
        b.OwnerUserId,
        b.OwnerRoleFamilyAtCreation,
        b.AgencyId,
        b.CorporateId,
        b.IsGuestBooking,
        b.Type,
        b.Status,
        b.Amount,
        b.CreatedAt);
}
