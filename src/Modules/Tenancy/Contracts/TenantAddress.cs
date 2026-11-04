using System.Globalization;

namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>
/// What a Tenant Subdomain gives a Tenant (FR-7, AD-6), built here and nowhere else, once, at
/// creation, and then stored and only read: the host <c>{subdomain}.{zone}</c>; the issuer
/// <c>https://{host}/</c>, with <c>:{port}</c> before the slash only when the Tenant HTTPS port
/// isn't 443, an origin with only the root path as the Story 2.1 spike compares it
/// (<see cref="Uri.AbsoluteUri"/>); the WebAuthn RP ID, which is the host and never has a port; and
/// the email link base, which is the issuer. Nothing recomputes these from a request or from
/// configuration after creation.
/// </summary>
public sealed record TenantAddress
{
    private TenantAddress(string host, string issuer, string rpId, string emailLinkBase)
    {
        Host = host;
        Issuer = issuer;
        RpId = rpId;
        EmailLinkBase = emailLinkBase;
    }

    public string Host { get; }

    public string Issuer { get; }

    public string RpId { get; }

    public string EmailLinkBase { get; }

    /// <exception cref="ArgumentException"><paramref name="zone"/> isn't a valid Tenant zone.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="httpsPort"/> isn't 1 to 65535.</exception>
    public static TenantAddress For(TenantSubdomain subdomain, string zone, int httpsPort)
    {
        ArgumentNullException.ThrowIfNull(subdomain);
        if (!TenantZone.IsValid(zone))
        {
            throw new ArgumentException("The Tenant zone is lower-case LDH labels, at least two.", nameof(zone));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(httpsPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(httpsPort, 65535);

        var host = $"{subdomain.Value}.{zone}";
        var issuer = httpsPort == 443
            ? $"https://{host}/"
            : $"https://{host}:{httpsPort.ToString(CultureInfo.InvariantCulture)}/";

        return new TenantAddress(host, issuer, host, issuer);
    }
}
