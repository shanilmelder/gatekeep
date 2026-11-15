using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>A save's input once every field passed: the kind, its settings as stored, the From parts and the secret, if given.</summary>
internal sealed record ValidProvider(
    string Kind,
    EmailProviderSettings Settings,
    string FromAddress,
    string? FromName,
    Secret<string>? Secret)
{
    /// <summary>Whether this kind and its settings send with a secret: every kind but SMTP with no username.</summary>
    public bool UsesSecret => EmailProviderRules.UsesSecret(Kind, Settings);
}

/// <summary>
/// The configuration rules of an email provider (Story 4.4): each kind's settings, the From address and name, and
/// the secret. Only the configuration: how a request is shaped and the outbound checks on resolved addresses
/// belong to sending (Story 4.5). Every refusal names the field and why, never the value.
/// </summary>
internal static partial class EmailProviderRules
{
    /// <summary>The default header a Custom HTTP provider's secret is sent in.</summary>
    public const string DefaultAuthHeaderName = "Authorization";

    private const int MaxHostLength = 253;
    private const int MaxUsernameLength = 256;
    private const int MaxMessageStreamLength = 64;
    private const int MaxEndpointLength = 2048;
    private const int MaxAuthHeaderNameLength = 64;
    private const int MaxAccessKeyIdLength = 128;
    private const int MaxRegionLength = 64;
    private const int MaxTlsLength = 16;

    private static readonly SearchValues<char> TokenCharacters =
        SearchValues.Create("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    /// <summary>The members each kind's settings may hold.</summary>
    private static readonly Dictionary<string, string[]> Members = new(StringComparer.Ordinal)
    {
        [EmailProviderKinds.Smtp] = ["host", "port", "tls", "username"],
        [EmailProviderKinds.SendGrid] = ["region"],
        [EmailProviderKinds.Postmark] = ["messageStream"],
        [EmailProviderKinds.Mailgun] = ["domain", "region"],
        [EmailProviderKinds.Ses] = ["region", "accessKeyId"],
        [EmailProviderKinds.CustomHttp] = ["endpoint", "authHeaderName"],
    };

    /// <summary>Whether <paramref name="kind"/> with <paramref name="settings"/> sends with a secret.</summary>
    public static bool UsesSecret(string kind, EmailProviderSettings settings) =>
        kind != EmailProviderKinds.Smtp || settings.Username is not null;

    /// <summary>The input's fields, each checked on its own: the errors, empty when <paramref name="valid"/> is set.</summary>
    public static List<EmailProviderFieldError> Validate(EmailProviderInput input, out ValidProvider? valid)
    {
        ArgumentNullException.ThrowIfNull(input);
        valid = null;
        var errors = new List<EmailProviderFieldError>();

        string? kind = null;
        if (input.Kind is null)
        {
            errors.Add(new(EmailProviderFields.Kind, EmailProviderReasons.Required));
        }
        else if (!Members.ContainsKey(input.Kind))
        {
            errors.Add(new(EmailProviderFields.Kind, EmailProviderReasons.Invalid));
        }
        else
        {
            kind = input.Kind;
        }

        EmailProviderSettings? settings = null;
        if (input.Settings is not { } element || element.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            errors.Add(new(EmailProviderFields.Settings, EmailProviderReasons.Required));
        }
        else if (element.ValueKind != JsonValueKind.Object)
        {
            errors.Add(new(EmailProviderFields.Settings, EmailProviderReasons.Invalid));
        }
        else if (kind is not null)
        {
            settings = Settings(kind, element, errors);
        }

        var fromAddress = FromAddress(input.FromAddress, errors);
        var fromName = FromName(input.FromName, errors);

        if (input.Secret is { } secret)
        {
            var reason = secret.Use(static value =>
                value.Length == 0 || value.Contains('\0', StringComparison.Ordinal) ? EmailProviderReasons.Invalid
                : value.Length > SecurityLimits.MaxEmailProviderSecretLength ? EmailProviderReasons.TooLong
                : null);
            if (reason is not null)
            {
                errors.Add(new(EmailProviderFields.Secret, reason));
            }
            else if (kind is not null && settings is not null && !UsesSecret(kind, settings))
            {
                // SMTP with no username sends with no password: a secret here would never be used.
                errors.Add(new(EmailProviderFields.Secret, EmailProviderReasons.Invalid));
            }
        }

        if (errors.Count == 0)
        {
            valid = new ValidProvider(kind!, settings!, fromAddress!, fromName, input.Secret);
        }

        return errors;
    }

    /// <summary>The settings as stored, as canonical JSON with only the members set, in a fixed order.</summary>
    public static string Json(EmailProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            WriteString(writer, "host", settings.Host);
            if (settings.Port is { } port)
            {
                writer.WriteNumber("port", port);
            }

            WriteString(writer, "tls", settings.Tls);
            WriteString(writer, "username", settings.Username);
            WriteString(writer, "region", settings.Region);
            WriteString(writer, "messageStream", settings.MessageStream);
            WriteString(writer, "domain", settings.Domain);
            WriteString(writer, "accessKeyId", settings.AccessKeyId);
            WriteString(writer, "endpoint", settings.Endpoint);
            WriteString(writer, "authHeaderName", settings.AuthHeaderName);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>Settings read back from their stored JSON: only the known members, as the save wrote them.</summary>
    public static EmailProviderSettings Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        return new EmailProviderSettings
        {
            Host = StoredString(root, "host"),
            Port = root.TryGetProperty("port", out var port) && port.ValueKind == JsonValueKind.Number && port.TryGetInt32(out var value) ? value : null,
            Tls = StoredString(root, "tls"),
            Username = StoredString(root, "username"),
            Region = StoredString(root, "region"),
            MessageStream = StoredString(root, "messageStream"),
            Domain = StoredString(root, "domain"),
            AccessKeyId = StoredString(root, "accessKeyId"),
            Endpoint = StoredString(root, "endpoint"),
            AuthHeaderName = StoredString(root, "authHeaderName"),
        };
    }

    private static string? StoredString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static void WriteString(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
        {
            writer.WriteString(name, value);
        }
    }

    private static EmailProviderSettings? Settings(string kind, JsonElement element, List<EmailProviderFieldError> errors)
    {
        var allowed = Members[kind];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var member in element.EnumerateObject())
        {
            // An unknown member, or one sent twice, is refused whole: never stored, never named.
            if (!allowed.Contains(member.Name, StringComparer.Ordinal) || !seen.Add(member.Name))
            {
                errors.Add(new(EmailProviderFields.Settings, EmailProviderReasons.Invalid));
                return null;
            }
        }

        var before = errors.Count;
        var settings = kind switch
        {
            EmailProviderKinds.Smtp => new EmailProviderSettings
            {
                Host = Required(element, "host", EmailProviderFields.Host, MaxHostLength, IsHost, errors),
                Port = Port(element, errors),
                Tls = Required(element, "tls", EmailProviderFields.Tls, MaxTlsLength, static v => v is "starttls" or "implicit", errors),
                Username = Optional(element, "username", EmailProviderFields.Username, MaxUsernameLength, static v => !v.Any(char.IsControl), errors),
            },
            EmailProviderKinds.SendGrid => new EmailProviderSettings
            {
                Region = Required(element, "region", EmailProviderFields.Region, MaxRegionLength, static v => v is "global" or "eu", errors),
            },
            EmailProviderKinds.Postmark => new EmailProviderSettings
            {
                MessageStream = Optional(element, "messageStream", EmailProviderFields.MessageStream, MaxMessageStreamLength, static v => MessageStreamPattern().IsMatch(v), errors),
            },
            EmailProviderKinds.Mailgun => new EmailProviderSettings
            {
                Domain = Required(element, "domain", EmailProviderFields.Domain, MaxHostLength, IsDnsName, errors),
                Region = Required(element, "region", EmailProviderFields.Region, MaxRegionLength, static v => v is "us" or "eu", errors),
            },
            EmailProviderKinds.Ses => new EmailProviderSettings
            {
                Region = Required(element, "region", EmailProviderFields.Region, MaxRegionLength, static v => SesRegionPattern().IsMatch(v), errors),
                AccessKeyId = Required(element, "accessKeyId", EmailProviderFields.AccessKeyId, MaxAccessKeyIdLength, static v => AccessKeyIdPattern().IsMatch(v), errors),
            },
            _ => new EmailProviderSettings
            {
                Endpoint = Required(element, "endpoint", EmailProviderFields.Endpoint, MaxEndpointLength, IsEndpoint, errors),
                AuthHeaderName = Optional(element, "authHeaderName", EmailProviderFields.AuthHeaderName, MaxAuthHeaderNameLength, IsToken, errors)
                    ?? DefaultAuthHeaderName,
            },
        };

        return errors.Count == before ? settings : null;
    }

    private static int? Port(JsonElement element, List<EmailProviderFieldError> errors)
    {
        if (!element.TryGetProperty("port", out var value) || value.ValueKind == JsonValueKind.Null)
        {
            errors.Add(new(EmailProviderFields.Port, EmailProviderReasons.Required));
            return null;
        }

        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var port) || port is < 1 or > 65535)
        {
            errors.Add(new(EmailProviderFields.Port, EmailProviderReasons.Invalid));
            return null;
        }

        return port;
    }

    /// <summary>A required string member: absent or null is required, another type or a value <paramref name="valid"/> refuses is invalid.</summary>
    private static string? Required(
        JsonElement element, string name, string field, int maxLength, Func<string, bool> valid, List<EmailProviderFieldError> errors)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            errors.Add(new(field, EmailProviderReasons.Required));
            return null;
        }

        return Checked(value, field, maxLength, valid, errors);
    }

    /// <summary>An optional string member: absent, null, empty or only white space is none.</summary>
    private static string? Optional(
        JsonElement element, string name, string field, int maxLength, Func<string, bool> valid, List<EmailProviderFieldError> errors)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null
            || (value.ValueKind == JsonValueKind.String && string.IsNullOrWhiteSpace(value.GetString())))
        {
            return null;
        }

        return Checked(value, field, maxLength, valid, errors);
    }

    private static string? Checked(JsonElement value, string field, int maxLength, Func<string, bool> valid, List<EmailProviderFieldError> errors)
    {
        if (value.ValueKind != JsonValueKind.String)
        {
            errors.Add(new(field, EmailProviderReasons.Invalid));
            return null;
        }

        var text = value.GetString()!;
        if (text.Length > maxLength)
        {
            errors.Add(new(field, EmailProviderReasons.TooLong));
            return null;
        }

        if (text.Length == 0 || !valid(text))
        {
            errors.Add(new(field, EmailProviderReasons.Invalid));
            return null;
        }

        return text;
    }

    private static string? FromAddress(string? input, List<EmailProviderFieldError> errors)
    {
        if (string.IsNullOrEmpty(input))
        {
            errors.Add(new(EmailProviderFields.FromAddress, EmailProviderReasons.Required));
            return null;
        }

        if (input.Length > SecurityLimits.MaxEmailLength)
        {
            errors.Add(new(EmailProviderFields.FromAddress, EmailProviderReasons.TooLong));
            return null;
        }

        if (!IsEmailAddress(input))
        {
            errors.Add(new(EmailProviderFields.FromAddress, EmailProviderReasons.Invalid));
            return null;
        }

        return input;
    }

    private static string? FromName(string? input, List<EmailProviderFieldError> errors)
    {
        if (string.IsNullOrEmpty(input))
        {
            return null;
        }

        if (input.Length > SecurityLimits.MaxEmailFromNameLength)
        {
            errors.Add(new(EmailProviderFields.FromName, EmailProviderReasons.TooLong));
            return null;
        }

        if (input.Any(char.IsControl))
        {
            errors.Add(new(EmailProviderFields.FromName, EmailProviderReasons.Invalid));
            return null;
        }

        return input;
    }

    /// <summary>One <c>@</c> with a local part and a dotted DNS domain, no whitespace or control character, as a mail header can carry it.</summary>
    internal static bool IsEmailAddress(string value)
    {
        if (value.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c) || c > '~'))
        {
            return false;
        }

        var at = value.LastIndexOf('@');
        if (at <= 0 || at != value.IndexOf('@') || at == value.Length - 1 || at > 64)
        {
            return false;
        }

        var domain = value[(at + 1)..];
        return domain.Contains('.', StringComparison.Ordinal)
            && IsDnsName(domain)
            && System.Net.Mail.MailAddress.TryCreate(value, out var parsed)
            && string.Equals(parsed.Address, value, StringComparison.Ordinal)
            && string.IsNullOrEmpty(parsed.DisplayName);
    }

    /// <summary>An SMTP host: a DNS name, or an IPv4 or IPv6 literal that is a public address.</summary>
    internal static bool IsHost(string value)
    {
        if (value.Contains(':', StringComparison.Ordinal) || IPv4Pattern().IsMatch(value))
        {
            return IPAddress.TryParse(value, out var address) && IsPublic(address);
        }

        return IsDnsName(value);
    }

    /// <summary>
    /// A DNS name: dot-separated labels of letters, digits and inner hyphens, each 1 to 63 characters, at most 253 in all,
    /// whose last label isn't all digits. Never <c>localhost</c> or a name under it.
    /// </summary>
    internal static bool IsDnsName(string value)
    {
        if (value.Length is 0 or > MaxHostLength)
        {
            return false;
        }

        var labels = value.Split('.');
        if (labels.Any(static l => !DnsLabelPattern().IsMatch(l)) || labels[^1].All(char.IsAsciiDigit))
        {
            return false;
        }

        return !string.Equals(labels[^1], "localhost", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A Custom HTTP endpoint: an absolute <c>https</c> URL with no userinfo or fragment, whose host is a DNS name other than
    /// <c>localhost</c>, or an IP literal that isn't loopback, private, link-local or unspecified. Resolved addresses and
    /// redirects are checked when sending (Story 4.5).
    /// </summary>
    internal static bool IsEndpoint(string value)
    {
        if (value.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c)) || value.Contains('#', StringComparison.Ordinal)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !value.StartsWith(Uri.UriSchemeHttps + Uri.SchemeDelimiter, StringComparison.OrdinalIgnoreCase)
            || uri.UserInfo.Length > 0
            || value[8..].Split('/', 2)[0].Contains('@', StringComparison.Ordinal))
        {
            return false;
        }

        return uri.HostNameType switch
        {
            UriHostNameType.IPv4 or UriHostNameType.IPv6 => IPAddress.TryParse(uri.DnsSafeHost, out var address) && IsPublic(address),
            UriHostNameType.Dns => IsDnsName(uri.IdnHost),
            _ => false,
        };
    }

    /// <summary>An HTTP header name: an RFC 9110 token.</summary>
    internal static bool IsToken(string value) => value.Length > 0 && !value.AsSpan().ContainsAnyExcept(TokenCharacters);

    /// <summary>
    /// Whether an IP literal may be a provider's address: not unspecified, loopback, private, shared, link-local,
    /// documentation, benchmarking, multicast or reserved. An IPv4-mapped IPv6 address is judged by its IPv4 address; one
    /// that carries an IPv4 address otherwise (NAT64, 6to4, IPv4-compatible) is refused, as is IPv6 documentation.
    /// </summary>
    internal static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] is 0 or 10 or 127 or >= 224
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2)
                || (b[0] == 192 && b[1] == 88 && b[2] == 99)
                || (b[0] == 198 && b[1] is 18 or 19)
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                || (b[0] == 203 && b[1] == 0 && b[2] == 113));
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        var ipv4Compatible = bytes.AsSpan(0, 12).IndexOfAnyExcept((byte)0) < 0;
        return !(ipv4Compatible
            || (bytes[0] & 0xfe) == 0xfc
            || (bytes[0] == 0xfe && (bytes[1] & 0xc0) is 0x80 or 0xc0)
            || bytes[0] == 0xff
            || (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b)
            || (bytes[0] == 0x20 && bytes[1] == 0x02)
            || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8));
    }

    [GeneratedRegex(@"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z", RegexOptions.CultureInvariant)]
    private static partial Regex DnsLabelPattern();

    [GeneratedRegex(@"\A[0-9]{1,3}(?:\.[0-9]{1,3}){3}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IPv4Pattern();

    [GeneratedRegex(@"\A[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex MessageStreamPattern();

    [GeneratedRegex(@"\A[a-z]{2}(?:-[a-z]+)+-[0-9]\z", RegexOptions.CultureInvariant)]
    private static partial Regex SesRegionPattern();

    [GeneratedRegex(@"\A[A-Z0-9]{16,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex AccessKeyIdPattern();
}
