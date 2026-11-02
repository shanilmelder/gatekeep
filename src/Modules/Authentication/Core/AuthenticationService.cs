using System.Buffers.Text;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;

namespace Gatekeep.Modules.Authentication.Core;

internal sealed class AuthenticationService(IAuditAppender audit, TimeProvider time) : IAuthentication
{
    private static readonly AuditTypeCode Started = AuthenticationEvents.SignInTransactionStarted.Code;

    private const string InsertTransaction =
        """
        INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at)
        VALUES (@tenant_id, @id, @application_id, @binding_hash, @parameters::jsonb, @created_at, @expires_at)
        """;

    /// <summary>The largest serialized parameter set a sign-in stores: 16 KiB.</summary>
    private const int MaxParametersBytes = 16 * 1024;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));

    public async Task<StartedSignIn> BeginAsync(
        CommandContext context,
        SignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A sign-in begins only in a Tenant context.");

        if (request.ApplicationId == Guid.Empty)
        {
            throw new ArgumentException("A sign-in needs an Application.", nameof(request));
        }

        var parameters = SerializedParameters(request.Parameters);

        var now = _time.GetUtcNow();
        var id = Guid.CreateVersion7(now);
        var (binding, hash) = NewOpaqueValue();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertTransaction;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", id);
            Add(command, "application_id", request.ApplicationId);
            Add(command, "binding_hash", hash);
            Add(command, "parameters", parameters);
            Add(command, "created_at", now);
            Add(command, "expires_at", now + SecurityLimits.SignInTransactionLifetime);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // Nobody is signed in yet, and the envelope has no Application target kind.
        await _audit.AppendAsync(context, new AuditEvent(Started, Actor.Anonymous), detail: null, cancellationToken);

        return new StartedSignIn(id, binding);
    }

    /// <summary>
    /// The anonymous caller's parameters as JSON, refused before any write when jsonb can't
    /// hold them (a NUL character) or they are null or too large.
    /// </summary>
    private static string SerializedParameters(IReadOnlyDictionary<string, string>? parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentException("A sign-in needs its parameters.", nameof(parameters));
        }

        foreach (var (key, value) in parameters)
        {
            if (value is null || key.Contains('\0') || value.Contains('\0'))
            {
                throw new ArgumentException("A sign-in parameter is null or holds a NUL character.", nameof(parameters));
            }
        }

        var json = JsonSerializer.Serialize(parameters);
        if (Encoding.UTF8.GetByteCount(json) > MaxParametersBytes)
        {
            throw new ArgumentException("The sign-in parameters are too large.", nameof(parameters));
        }

        return json;
    }

    /// <summary>
    /// 256 random bits as base64url, and the SHA-256 of that text's ASCII bytes, which is all
    /// that's stored. A cookie value is looked up by hashing it the same way.
    /// </summary>
    private static (Secret<string> Value, byte[] Hash) NewOpaqueValue()
    {
        var random = RandomNumberGenerator.GetBytes(32);

        try
        {
            var value = Base64Url.EncodeToString(random);
            return (new Secret<string>(value), SHA256.HashData(Encoding.ASCII.GetBytes(value)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
