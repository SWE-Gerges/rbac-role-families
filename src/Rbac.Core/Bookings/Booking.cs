using Rbac.Abstractions;

namespace Rbac.Core.Bookings;

public enum CancelOutcome
{
    Cancelled,
    NotCancellable,
}

/// <summary>
/// A booking. Its ownership (tenant, owner, family, agency, corporate) is stamped once at write time
/// and never recomputed from the creator's current role.
/// </summary>
public sealed class Booking
{
    // Required by EF Core.
    private Booking()
    {
    }

    public string Id { get; private set; } = string.Empty;

    public string TenantId { get; private set; } = string.Empty;

    public string OwnerUserId { get; private set; } = string.Empty;

    /// <summary>The creator's family when the booking was written. Null for customers and guests.</summary>
    public RoleFamily? OwnerRoleFamilyAtCreation { get; private set; }

    public string? AgencyId { get; private set; }

    public string? CorporateId { get; private set; }

    public bool IsGuestBooking { get; private set; }

    public BookingType Type { get; private set; }

    public BookingStatus Status { get; private set; }

    public decimal Amount { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public static Booking Create(
        string id,
        OwnershipStamp stamp,
        bool isGuestBooking,
        BookingType type,
        BookingStatus status,
        decimal amount,
        DateTimeOffset createdAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(stamp);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);

        return new Booking
        {
            Id = id,
            TenantId = stamp.TenantId,
            OwnerUserId = stamp.OwnerUserId,
            OwnerRoleFamilyAtCreation = stamp.OwnerRoleFamily,
            AgencyId = stamp.AgencyId,
            CorporateId = stamp.CorporateId,
            IsGuestBooking = isGuestBooking,
            Type = type,
            Status = status,
            Amount = amount,
            CreatedAt = createdAt,
        };
    }

    public CancelOutcome Cancel()
    {
        if (Status is not (BookingStatus.Draft or BookingStatus.Confirmed))
        {
            return CancelOutcome.NotCancellable;
        }

        Status = BookingStatus.Cancelled;
        return CancelOutcome.Cancelled;
    }
}
