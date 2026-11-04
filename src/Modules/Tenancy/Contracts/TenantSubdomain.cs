using System.Collections.Frozen;

namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>
/// A Tenant Subdomain as the create request sent it (FR-7, AD-6): taken exactly as sent, with no
/// trimming or case folding; 3 to 63 of <c>a–z</c>, <c>0–9</c> and <c>-</c>; not starting or
/// ending with <c>-</c>; no <c>--</c> at positions 3 and 4, so no <c>xn--</c> or other IDNA label;
/// not in <see cref="ReservedSubdomains"/>; and with its zone, a host of at most 253 characters.
/// It is read only at creation: nothing ever parses one back out of a host.
/// </summary>
public sealed class TenantSubdomain
{
    public const int MinLength = 3;

    public const int MaxLength = 63;

    /// <summary>The longest host DNS allows, and so the longest <c>{subdomain}.{zone}</c>.</summary>
    public const int MaxHostLength = 253;

    private TenantSubdomain(string value) => Value = value;

    public string Value { get; }

    public override string ToString() => Value;

    /// <summary>
    /// Whether <paramref name="text"/> is a usable Tenant Subdomain under <paramref name="zone"/>.
    /// A malformed and a reserved value are both false: nothing tells them apart.
    /// </summary>
    public static bool TryParse(string? text, string zone, out TenantSubdomain subdomain)
    {
        ArgumentNullException.ThrowIfNull(zone);
        subdomain = null!;

        if (!IsWellFormed(text)
            || ReservedSubdomains.Contains(text!)
            || text!.Length + 1 + zone.Length > MaxHostLength)
        {
            return false;
        }

        subdomain = new TenantSubdomain(text);
        return true;
    }

    /// <summary>The shape rule alone, without the reserved list or the zone: what the dashboard checks too.</summary>
    public static bool IsWellFormed(string? text)
    {
        if (text is null || text.Length is < MinLength or > MaxLength)
        {
            return false;
        }

        foreach (var c in text)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
            {
                return false;
            }
        }

        return text[0] != '-' && text[^1] != '-' && !(text[2] == '-' && text[3] == '-');
    }
}

/// <summary>
/// The code-owned infrastructure names no Tenant may take (AD-6) <c>[ASSUMPTION]</c>. Each is
/// refused exactly as a taken one is. <c>id</c> is already refused by the length rule; it is
/// listed so the list stands alone.
/// </summary>
public static class ReservedSubdomains
{
    public static readonly FrozenSet<string> All = FrozenSet.ToFrozenSet(
    [
        "account", "accounts", "admin", "api", "app", "apps", "assets", "auth", "autoconfig", "autodiscover",
        "billing", "cdn", "connect", "console", "dashboard", "dns", "docs", "email", "ftp", "gatekeep",
        "health", "help", "id", "identity", "imap", "internal", "isatap", "localhost", "login", "logout",
        "mail", "mta-sts", "mx", "ns", "ns1", "ns2", "oauth", "oidc", "openpgpkey", "pop",
        "pop3", "root", "sftp", "smtp", "sso", "static", "status", "support", "system", "vpn",
        "webmail", "wpad", "www",
    ], StringComparer.Ordinal);

    public static bool Contains(string subdomain) => All.Contains(subdomain);
}

/// <summary>
/// The Tenant zone every Tenant Subdomain sits under, such as <c>gatekeep.example.com</c>: lower-case
/// LDH labels of 1 to 63 characters, neither starting nor ending with <c>-</c>, separated by dots, at
/// least two of them, and at most 200 characters in all <c>[ASSUMPTION]</c>.
/// </summary>
public static class TenantZone
{
    public const int MaxLength = 200;

    public static bool IsValid(string? zone)
    {
        if (string.IsNullOrEmpty(zone) || zone.Length > MaxLength)
        {
            return false;
        }

        var labels = zone.Split('.');
        if (labels.Length < 2)
        {
            return false;
        }

        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (var c in label)
            {
                if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Whether <paramref name="host"/> is the zone itself or a name under it, case-insensitively:
    /// the Admin hostname must sit outside the zone (AD-6).
    /// </summary>
    public static bool Covers(string zone, string host)
    {
        ArgumentNullException.ThrowIfNull(zone);
        ArgumentNullException.ThrowIfNull(host);

        var name = host.TrimEnd('.');
        return name.Equals(zone, StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase);
    }
}
