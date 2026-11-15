using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>
/// An email provider save's body (Story 4.4): the kind, its settings, the From address and name, and the provider's
/// secret. The save replaces what is stored; only the secret may be left out to keep the one stored.
/// </summary>
public sealed class SetEmailProviderRequest
{
    /// <summary><c>smtp</c>, <c>sendgrid</c>, <c>postmark</c>, <c>mailgun</c>, <c>ses</c> or <c>custom_http</c>.</summary>
    public string? Kind { get; init; }

    /// <summary>The kind's non-secret settings, and no other member: see <c>EmailProviderSettings</c>.</summary>
    public JsonElement? Settings { get; init; }

    /// <summary>The address messages are sent from: a valid email address of at most 254 characters.</summary>
    public string? FromAddress { get; init; }

    /// <summary>The name messages are sent from: optional, at most 128 characters, with no control character.</summary>
    public string? FromName { get; init; }

    /// <summary>
    /// The SMTP password, API key, server token, secret access key or auth header value: 1 to 4096 characters with no
    /// NUL. Required on a first save, a change of kind, an SMTP username with none stored, and any change of settings
    /// but Postmark's message stream; left out otherwise, the stored one stays. Never returned, stored only encrypted.
    /// </summary>
    public string? Secret { get; init; }
}

/// <summary>An email provider's non-secret settings: only its kind's members are present (Story 4.4).</summary>
public sealed class EmailProviderSettings
{
    /// <summary><c>smtp</c>: a DNS name or a public IP address, at most 253 characters.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Host { get; init; }

    /// <summary><c>smtp</c>: 1 to 65535.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Port { get; init; }

    /// <summary><c>smtp</c>: <c>starttls</c> or <c>implicit</c>; never plaintext.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tls { get; init; }

    /// <summary><c>smtp</c>, optional: at most 256 characters. With one, the secret is its password.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; init; }

    /// <summary><c>sendgrid</c>: <c>global</c> or <c>eu</c>. <c>mailgun</c>: <c>us</c> or <c>eu</c>. <c>ses</c>: an AWS region, such as <c>eu-west-1</c>.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Region { get; init; }

    /// <summary><c>postmark</c>, optional: 1 to 64 letters, digits, hyphens and underscores.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MessageStream { get; init; }

    /// <summary><c>mailgun</c>: the sending domain, a DNS name of at most 253 characters.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Domain { get; init; }

    /// <summary><c>ses</c>: the access key ID, 16 to 128 upper-case letters and digits.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AccessKeyId { get; init; }

    /// <summary>
    /// <c>custom_http</c>: an absolute https URL of at most 2048 characters, with no userinfo or fragment, whose host
    /// isn't localhost or a loopback, private, link-local or unspecified IP address.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Endpoint { get; init; }

    /// <summary><c>custom_http</c>: the HTTP header the secret is sent in, a token of at most 64 characters; <c>Authorization</c> by default.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthHeaderName { get; init; }
}

/// <summary>A Tenant's email provider (Story 4.4): <c>configured</c> only when it has none. Never its secret or ciphertext.</summary>
public sealed class EmailProviderResponse
{
    /// <summary>Whether the Tenant has an email provider. When false, no other member is present.</summary>
    public required bool Configured { get; init; }

    /// <summary><c>smtp</c>, <c>sendgrid</c>, <c>postmark</c>, <c>mailgun</c>, <c>ses</c> or <c>custom_http</c>.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Kind { get; init; }

    /// <summary>The kind's non-secret settings, as stored.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public EmailProviderSettings? Settings { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FromAddress { get; init; }

    /// <summary>Absent when none is set.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FromName { get; init; }

    /// <summary>When it was last changed, ISO 8601 in UTC.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UpdatedAt { get; init; }

    /// <summary>Whether a secret is stored: always, but for SMTP with no username, which sends with none. The secret itself never leaves.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? SecretSet { get; init; }
}

/// <summary>
/// A Tenant's email provider (Story 4.4, FR-36, FR-46, AD-10): read with any Tenant Role, saved and removed by its
/// Tenant Owner only, never a machine principal, always after a fresh assertion, which the request checks decide. All
/// run in the path Tenant's own scope, and Management decides the capability again from the same grant. The secret is
/// encrypted in the request under the Tenant's email key, which Host.Admin may never decrypt, and is never stored,
/// logged or returned as given.
/// </summary>
internal static class EmailProviderApi
{
    /// <summary>
    /// The largest save body: room for a 4096-character secret with every UTF-16 unit escaped as JSON (6 bytes each), and
    /// the longest settings and From parts. Anything bigger is 400 <c>email_provider_invalid</c>, unread past it.
    /// </summary>
    public const int MaxBody = 65536;

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        EmailProviderResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.EmailProviders.GetAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (result.Status != EmailProviderStatus.Done)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
            return;
        }

        await AdminResponses.JsonAsync(context, Response(result.Provider));
    }

    public static async Task SetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;
        var custody = context.RequestServices.GetService<IKeyCustody>();

        // Under a deadline and a size cap, as application/json only: anything else is malformed, and refused before
        // anything is read or written.
        var body = await AdminApi.ReadJsonAsync<SetEmailProviderRequest>(context.Request, MaxBody, cancellationToken);
        if (body is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.EmailProviderInvalid);
            return;
        }

        var input = new EmailProviderSaveInput(
            body.Kind,
            body.Settings,
            body.FromAddress,
            body.FromName,
            body.Secret is { } secret ? new Secret<string>(secret) : null);

        EmailProviderResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.EmailProviders.SaveAsync(
                scope.CreateCommandContext(), custody, principal, path.Grant, path.TenantId, input, cancellationToken);

            if (result.Status == EmailProviderStatus.Done)
            {
                // The row, its ciphertext and its event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case EmailProviderStatus.Done:
                await AdminResponses.JsonAsync(context, Response(result.Provider), cancellationToken: CancellationToken.None);
                return;

            case EmailProviderStatus.Invalid:
                LogRefusal(context, AdminResponses.EmailProviderInvalid);
                await AdminResponses.ProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AdminResponses.EmailProviderInvalid,
                    [.. result.Errors.Select(e => new ApiProblemError { Field = e.Field, Index = null, Reason = e.Reason })]);
                return;

            case EmailProviderStatus.Unavailable:
                // The failure's kind only: never a key name, the secret or what custody answered.
                Logger(context).LogWarning(
                    "Key custody couldn't encrypt an email provider secret, trace {TraceId}.", AdminResponses.TraceId(context));
                await AdminResponses.UnavailableAsync(context);
                return;

            case EmailProviderStatus.Forbidden:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;

            default:
                throw new InvalidOperationException("Unknown email provider status.");
        }
    }

    public static async Task RemoveAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        EmailProviderResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.EmailProviders.RemoveAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);

            if (result.Status == EmailProviderStatus.Done)
            {
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (result.Status != EmailProviderStatus.Done)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
            return;
        }

        // The same answer whether a provider was removed or there was none.
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        context.Response.Headers.CacheControl = "no-store";
    }

    private static EmailProviderResponse Response(ManagedEmailProvider? provider) => provider is null
        ? new EmailProviderResponse { Configured = false }
        : new EmailProviderResponse
        {
            Configured = true,
            Kind = provider.Kind,
            Settings = new EmailProviderSettings
            {
                Host = provider.Settings.Host,
                Port = provider.Settings.Port,
                Tls = provider.Settings.Tls,
                Username = provider.Settings.Username,
                Region = provider.Settings.Region,
                MessageStream = provider.Settings.MessageStream,
                Domain = provider.Settings.Domain,
                AccessKeyId = provider.Settings.AccessKeyId,
                Endpoint = provider.Settings.Endpoint,
                AuthHeaderName = provider.Settings.AuthHeaderName,
            },
            FromAddress = provider.FromAddress,
            FromName = provider.FromName,
            UpdatedAt = ApplicationsApi.Timestamp(provider.UpdatedAt),
            SecretSet = provider.SecretSet,
        };

    /// <summary>A refusal, logged under its fixed code only: never a setting, an address or the secret.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        LogRefusal(context, problem);
        return AdminResponses.ProblemAsync(context, status, problem);
    }

    private static void LogRefusal(HttpContext context, string problem) =>
        Logger(context).LogInformation(
            "An email provider request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");
}
